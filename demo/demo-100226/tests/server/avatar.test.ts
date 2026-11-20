import { test } from 'node:test';
import assert from 'node:assert/strict';
import sharp from 'sharp';
import {
  AvatarInputError,
  normalizeAvatar,
  sanitizeAvatar,
  sanitizeStoredAvatar,
} from '../../server/avatar';
import { AVATAR_SOURCE_MAX_BYTES } from '../../src/lib/avatar';

const fallback = '/avatars/av-1.svg';

function source(width = 320, height = 180) {
  return sharp({
    create: {
      width,
      height,
      channels: 3,
      background: { r: 18, g: 110, b: 170 },
    },
  });
}

function decodedDataUrl(value: string): Buffer {
  return Buffer.from(value.slice(value.indexOf(',') + 1), 'base64');
}

test('PNG, JPEG, and WebP uploads are normalized to bounded 256x256 WebP data URLs', async () => {
  const inputs = [
    ['image/png', await source().png().toBuffer()],
    ['image/jpeg', await source().jpeg().toBuffer()],
    ['image/webp', await source().webp().toBuffer()],
  ] as const;

  for (const [mime, input] of inputs) {
    const avatar = await normalizeAvatar(input, mime);
    assert.match(avatar, /^data:image\/webp;base64,/);
    const output = decodedDataUrl(avatar);
    assert.ok(output.length > 0 && output.length <= 128 * 1024);
    const metadata = await sharp(output).metadata();
    assert.equal(metadata.format, 'webp');
    assert.equal(metadata.width, 256);
    assert.equal(metadata.height, 256);
  }
});

test('malformed bytes and invalid base64 are rejected without a fallback avatar', async () => {
  await assert.rejects(normalizeAvatar(Buffer.from('not an image'), 'image/png'), (error: unknown) => {
    assert.ok(error instanceof AvatarInputError);
    assert.equal(error.statusCode, 400);
    return true;
  });
  assert.equal(
    await sanitizeStoredAvatar('data:image/webp;base64,not*valid*base64', '/avatars/av-1.svg'),
    '/avatars/av-1.svg',
  );
});

test('declared MIME type must match the decoded image format', async () => {
  const webp = await source().webp().toBuffer();
  await assert.rejects(normalizeAvatar(webp, 'image/png'), (error: unknown) => {
    assert.ok(error instanceof AvatarInputError);
    assert.match(error.message, /content type/i);
    return true;
  });
});

test('oversized sources and excessive decoded dimensions are refused', async () => {
  await assert.rejects(
    normalizeAvatar(Buffer.alloc(AVATAR_SOURCE_MAX_BYTES + 1), 'image/png'),
    (error: unknown) => {
      assert.ok(error instanceof AvatarInputError);
      assert.equal(error.statusCode, 413);
      return true;
    },
  );

  const excessiveWidth = await source(4097, 1).png().toBuffer();
  await assert.rejects(normalizeAvatar(excessiveWidth, 'image/png'), (error: unknown) => {
    assert.ok(error instanceof AvatarInputError);
    assert.match(error.message, /dimensions/i);
    return true;
  });
});

test('legacy avatar sanitization retains only presets and valid bounded normalized images', async () => {
  const normalized = await normalizeAvatar(await source().png().toBuffer(), 'image/png');
  assert.equal(await sanitizeStoredAvatar(normalized, fallback), normalized);
  assert.equal(await sanitizeStoredAvatar('/avatars/av-3.svg', fallback), '/avatars/av-3.svg');

  for (const legacy of [
    'https://example.invalid/avatar.png',
    '/tmp/avatar.png',
    '<svg xmlns="http://www.w3.org/2000/svg"/>',
    'data:image/svg+xml;base64,PHN2Zy8+',
    'data:image/webp;base64,bm90LXdlYnA=',
    'javascript:alert(1)',
  ]) {
    assert.equal(await sanitizeStoredAvatar(legacy, fallback), fallback);
  }
});

test('synchronous response sanitization rejects arbitrary URLs and unknown presets', () => {
  assert.equal(sanitizeAvatar('https://example.invalid/avatar.png', fallback), fallback);
  assert.equal(sanitizeAvatar('/avatars/unknown.svg', fallback), fallback);
  assert.equal(sanitizeAvatar('/avatars/av-5.svg', fallback), '/avatars/av-5.svg');
});
