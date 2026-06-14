"use strict";

(() => {
"use strict";

function readU64Number(address, label) {
  const value = Number.parseInt(address.readU64().toString(10), 10);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} is outside JavaScript's safe integer range`);
  }
  return value;
}

function readU64BigInt(address) {
  return BigInt(address.readU64().toString(10));
}

function pointerNumber(value, label) {
  const text = value.toString();
  const parsed = Number.parseInt(text.startsWith("0x") ? text.slice(2) : text, text.startsWith("0x") ? 16 : 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} pointer is outside JavaScript's safe integer range: ${text}`);
  }
  return parsed;
}

function pointerDelta(start, end, label) {
  const startValue = pointerNumber(start, `${label} start`);
  const endValue = pointerNumber(end, `${label} end`);
  const value = endValue - startValue;
  if (value < 0) {
    throw new Error(
      `${label} pointer range is negative: start=${start.toString()} end=${end.toString()}`
    );
  }
  return value;
}

function snapshotBitReader(readerPtr, layout) {
  if (!layout) {
    return null;
  }
  if (readerPtr.isNull()) {
    throw new Error("reader pointer is null");
  }

  const tailBits = readU64Number(readerPtr.add(layout.tail_bits_offset), "tail bits");
  const availableBits = readerPtr.add(layout.available_bits_offset).readU32();
  const wordCursor = readerPtr.add(layout.word_cursor_offset).readPointer();
  const wordEnd = readerPtr.add(layout.word_end_offset).readPointer();
  const wordBytes = pointerDelta(wordCursor, wordEnd, "reader word cursor");
  const accumulator = readU64BigInt(readerPtr.add(layout.accumulator_offset));

  if (tailBits > 31) {
    throw new Error(`reader tail bits out of range: ${tailBits}`);
  }
  if (availableBits > 63) {
    throw new Error(`reader available bits out of range: ${availableBits}`);
  }
  if (wordBytes % 4 !== 0) {
    throw new Error(`reader word cursor range is not 32-bit aligned: ${wordBytes}`);
  }

  const remainingBits = availableBits + wordBytes * 8 + tailBits;
  if (remainingBits < 0 || remainingBits > layout.max_remaining_bits) {
    throw new Error(`reader remaining bits out of range: ${remainingBits}`);
  }

  return {
    native_layout: layout.name,
    accumulator,
    word_cursor: wordCursor,
    word_end: wordEnd,
    available_bits: availableBits,
    tail_bits: tailBits,
    word_bytes: wordBytes,
    remaining_bits: remainingBits,
  };
}

function setBit(bytes, bitIndex, bit) {
  if (bit !== 0) {
    bytes[Math.floor(bitIndex / 8)] |= 1 << (bitIndex % 8);
  }
}

function bitMask(width) {
  return (1n << BigInt(width)) - 1n;
}

function readTailValue(address, tailBits) {
  let value = 0n;
  const byteCount = Math.ceil(tailBits / 8);
  for (let i = 0; i < byteCount; i += 1) {
    value |= BigInt(address.add(i).readU8()) << BigInt(i * 8);
  }
  return value;
}

function cloneReaderState(snapshot) {
  return {
    native_layout: snapshot.native_layout,
    accumulator: snapshot.accumulator,
    word_cursor: snapshot.word_cursor,
    word_end: snapshot.word_end,
    available_bits: snapshot.available_bits,
    tail_bits: snapshot.tail_bits,
  };
}

function replayNativeRead(state, width) {
  if (width < 0 || width > 32) {
    throw new Error(`unsupported native read width: ${width}`);
  }
  if (width > state.available_bits) {
    throw new Error(`native read width ${width} exceeds available bits ${state.available_bits}`);
  }

  const value = width === 0 ? 0n : state.accumulator & bitMask(width);
  state.accumulator >>= BigInt(width);
  state.available_bits -= width;

  if (state.available_bits < 32) {
    if (state.word_cursor.compare(state.word_end) !== 0) {
      const word = BigInt(state.word_cursor.readU32());
      state.word_cursor = state.word_cursor.add(4);
      state.accumulator |= word << BigInt(state.available_bits);
      state.available_bits += 32;
    } else if (state.tail_bits !== 0) {
      const tailBits = state.tail_bits;
      const tail = readTailValue(state.word_end, tailBits);
      state.accumulator |= tail << BigInt(state.available_bits);
      state.available_bits += tailBits;
      state.tail_bits = 0;
    }
  }

  return value;
}

function finishStandaloneBitstream(out, bitCount) {
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  out[0] = (out[0] & 0xf8) | (paddingBits & 7);
  return {
    bytes: out.buffer,
    padding_bits: paddingBits,
    size: out.byteLength,
  };
}

function buildStandaloneBitstreamFromReadPlan(before, readPlan) {
  const bitCount = readPlan.reduce((total, width) => total + width, 0);
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  const out = new Uint8Array((totalBits + paddingBits) / 8);
  const replay = cloneReaderState(before);
  let outBit = 3;

  for (const width of readPlan) {
    const value = replayNativeRead(replay, width);
    for (let i = 0; i < width; i += 1) {
      setBit(out, outBit, Number((value >> BigInt(i)) & 1n));
      outBit += 1;
    }
  }

  return {
    standalone: finishStandaloneBitstream(out, bitCount),
    replay,
  };
}

function buildStandaloneBitstreamFromReadTrace(before, readTrace) {
  if (!readTrace || !Array.isArray(readTrace.reads) || readTrace.reads.length === 0) {
    throw new Error("reader trace has no native reads");
  }

  const bitCount = readTrace.reads.reduce((total, read) => total + read.width, 0);
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  const out = new Uint8Array((totalBits + paddingBits) / 8);
  const replay = cloneReaderState(before);
  let outBit = 3;

  for (const read of readTrace.reads) {
    const replayed = replayNativeRead(replay, read.width);
    if (read.value === null || read.value === undefined) {
      throw new Error(`reader trace read ${read.index} has no return value`);
    }
    if (replayed !== read.value) {
      throw new Error(
        `reader trace read ${read.index} value mismatch: native=${read.value.toString()} replay=${replayed.toString()} width=${read.width}`
      );
    }
    for (let i = 0; i < read.width; i += 1) {
      setBit(out, outBit, Number((read.value >> BigInt(i)) & 1n));
      outBit += 1;
    }
  }

  return {
    standalone: finishStandaloneBitstream(out, bitCount),
    replay,
  };
}

function buildStandaloneBitstreamFromWindowBits(before, bitCount) {
  const totalBits = 3 + bitCount;
  const paddingBits = (8 - (totalBits % 8)) & 7;
  const out = new Uint8Array((totalBits + paddingBits) / 8);
  const replay = cloneReaderState(before);
  let outBit = 3;

  for (let i = 0; i < bitCount; i += 1) {
    const value = replayNativeRead(replay, 1);
    setBit(out, outBit, Number(value & 1n));
    outBit += 1;
  }

  return {
    standalone: finishStandaloneBitstream(out, bitCount),
    replay,
  };
}

function replayMatchesSnapshot(replay, after) {
  return (
    replay.word_cursor.compare(after.word_cursor) === 0 &&
    replay.word_end.compare(after.word_end) === 0 &&
    replay.available_bits === after.available_bits &&
    replay.tail_bits === after.tail_bits &&
    replay.accumulator === after.accumulator
  );
}

function buildReaderWindow(before, after, layout, readPlan) {
  if (!before || !after) {
    return null;
  }
  if (before.native_layout !== after.native_layout) {
    throw new Error("reader layout changed during call");
  }
  if (!readPlan || readPlan.length === 0) {
    throw new Error("reader capture has no read plan");
  }

  const bitCount = before.remaining_bits - after.remaining_bits;
  if (bitCount === 0) {
    throw new Error("reader did not consume any bits");
  }
  if (bitCount < 0) {
    throw new Error("reader remaining bits increased during call");
  }
  if (bitCount > layout.max_window_bits) {
    throw new Error(`reader window is larger than max_window_bits: ${bitCount}`);
  }

  const plannedBits = readPlan.reduce((total, width) => total + width, 0);
  if (plannedBits !== bitCount) {
    throw new Error(`reader read-plan bits ${plannedBits} do not match native consumption ${bitCount}`);
  }

  const { standalone, replay } = buildStandaloneBitstreamFromReadPlan(before, readPlan);
  if (!replayMatchesSnapshot(replay, after)) {
    throw new Error("replayed reader state does not match native exit state");
  }

  return {
    metadata: {
      native_layout: layout.name,
      bit_count: bitCount,
      read_count: readPlan.length,
      remaining_bits_before: before.remaining_bits,
      remaining_bits_after: after.remaining_bits,
      standalone_size: standalone.size,
      standalone_padding_bits: standalone.padding_bits,
    },
    bytes: standalone.bytes,
    size: standalone.size,
  };
}

function buildReaderWindowFromTrace(before, after, layout, readTrace) {
  if (!before || !after) {
    return null;
  }
  if (before.native_layout !== after.native_layout) {
    throw new Error("reader layout changed during call");
  }
  if (readTrace.error) {
    throw new Error(readTrace.error);
  }

  const bitCount = before.remaining_bits - after.remaining_bits;
  if (bitCount === 0) {
    throw new Error("reader did not consume any bits");
  }
  if (bitCount < 0) {
    throw new Error("reader remaining bits increased during call");
  }
  if (bitCount > layout.max_window_bits) {
    throw new Error(`reader window is larger than max_window_bits: ${bitCount}`);
  }

  const tracedBits = readTrace.reads.reduce((total, read) => total + read.width, 0);
  if (tracedBits > bitCount) {
    throw new Error(`reader trace bits ${tracedBits} exceed native consumption ${bitCount}`);
  }

  const completeTrace = tracedBits === bitCount;
  const { standalone, replay } = completeTrace
    ? buildStandaloneBitstreamFromReadTrace(before, readTrace)
    : buildStandaloneBitstreamFromWindowBits(before, bitCount);
  if (!replayMatchesSnapshot(replay, after)) {
    throw new Error("replayed reader window state does not match native exit state");
  }

  return {
    metadata: {
      native_layout: layout.name,
      trace_source: completeTrace ? "BitReader::Read" : "reader-window",
      bit_count: bitCount,
      read_count: readTrace.reads.length,
      traced_bit_count: tracedBits,
      remaining_bits_before: before.remaining_bits,
      remaining_bits_after: after.remaining_bits,
      standalone_size: standalone.size,
      standalone_padding_bits: standalone.padding_bits,
    },
    bytes: standalone.bytes,
    size: standalone.size,
  };
}

globalThis.MSDELTA_STAGE_READER = Object.freeze({
  snapshotBitReader,
  buildReaderWindow,
  buildReaderWindowFromTrace,
});
})();
