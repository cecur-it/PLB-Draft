import sharp from 'sharp';
import { AVATAR_INPUT_TYPES, AVATAR_SOURCE_MAX_BYTES } from '../src/lib/avatar';

export const AVATAR_OUTPUT_MAX_BYTES = 128 * 1024;
export const AVATAR_OUTPUT_SIZE = 256;
export const AVATAR_SOURCE_MAX_DIMENSION = 4096;
const OUTPUT_PREFIX = 'data:image/webp;base64,';
export const AVATAR_DATA_URL_MAX_LENGTH = OUTPUT_PREFIX.length + Math.ceil(AVATAR_OUTPUT_MAX_BYTES / 3) * 4;

type AvatarInputType = (typeof AVATAR_INPUT_TYPES)[number];
const FORMAT_BY_MIME: Record<AvatarInputType, 'png' | 'jpeg' | 'webp'> = {
  'image/png': 'png',
  'image/jpeg': 'jpeg',
  'image/webp': 'webp',
};

export function isBoundedNormalizedAvatar(value: unknown): value is string {
  if (typeof value !== 'string' || !value.startsWith(OUTPUT_PREFIX) || value.length > AVATAR_DATA_URL_MAX_LENGTH) {
    return false;
  }
  const encoded = value.slice(OUTPUT_PREFIX.length);
  if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) return false;
  const bytes = Buffer.from(encoded, 'base64');
  return bytes.length > 12
    && bytes.length <= AVATAR_OUTPUT_MAX_BYTES
    && bytes.toString('base64') === encoded
    && bytes.subarray(0, 4).toString('ascii') === 'RIFF'
    && bytes.subarray(8, 12).toString('ascii') === 'WEBP'
    && bytes.readUInt32LE(4) === bytes.length - 8;
}

export function sanitizeAvatar(value: unknown, fallback: string): string {
  if (typeof value === 'string' && /^\/avatars\/av-[1-5]\.svg$/.test(value)) return value;
  return isBoundedNormalizedAvatar(value) ? value : fallback;
}

/** Persisted custom rasters are decoded once at boot; legacy URLs are never fetched. */
export async function sanitizeStoredAvatar(value: unknown, fallback: string): Promise<string> {
  const sanitized = sanitizeAvatar(value, fallback);
  if (sanitized === fallback || /^\/avatars\/av-[1-5]\.svg$/.test(sanitized)) return sanitized;
  if (!isBoundedNormalizedAvatar(sanitized)) return fallback;
  try {
    const bytes = Buffer.from(sanitized.slice(OUTPUT_PREFIX.length), 'base64');
    const metadata = await sharp(bytes, { failOn: 'error', limitInputPixels: AVATAR_OUTPUT_SIZE ** 2 }).metadata();
    return metadata.format === 'webp' && metadata.width === AVATAR_OUTPUT_SIZE && metadata.height === AVATAR_OUTPUT_SIZE
      ? sanitized
      : fallback;
  } catch {
    return fallback;
  }
}

export class AvatarInputError extends Error {
  constructor(message: string, public readonly statusCode = 400) {
    super(message);
    this.name = 'AvatarInputError';
  }
}

/** Decode untrusted bytes and return only a bounded, server-generated raster data URL. */
export async function normalizeAvatar(input: Buffer, contentType: string): Promise<string> {
  if (!Buffer.isBuffer(input) || input.length === 0) {
    throw new AvatarInputError('Choose a PNG, JPEG, or WebP image to upload.');
  }
  if (input.length > AVATAR_SOURCE_MAX_BYTES) {
    throw new AvatarInputError(`Avatar source exceeds the ${AVATAR_SOURCE_MAX_BYTES}-byte limit.`, 413);
  }
  if (!AVATAR_INPUT_TYPES.includes(contentType as AvatarInputType)) {
    throw new AvatarInputError('Avatar content type must be PNG, JPEG, or WebP.', 415);
  }

  try {
    const expectedFormat = FORMAT_BY_MIME[contentType as AvatarInputType];
    const metadata = await sharp(input, {
      failOn: 'error',
      limitInputPixels: 16_777_216,
      sequentialRead: true,
    }).metadata();
    if (metadata.format !== expectedFormat) {
      throw new AvatarInputError('Avatar bytes do not match the declared image content type.', 415);
    }
    if (!metadata.width || !metadata.height
      || metadata.width > AVATAR_SOURCE_MAX_DIMENSION
      || metadata.height > AVATAR_SOURCE_MAX_DIMENSION) {
      throw new AvatarInputError(`Avatar dimensions must be between 1 and ${AVATAR_SOURCE_MAX_DIMENSION} pixels per side.`, 422);
    }

    const output = await sharp(input, {
      failOn: 'error',
      limitInputPixels: 16_777_216,
      sequentialRead: true,
    })
      .rotate()
      .resize(AVATAR_OUTPUT_SIZE, AVATAR_OUTPUT_SIZE, { fit: 'cover', position: 'centre' })
      .webp({ quality: 82, alphaQuality: 80, effort: 4 })
      .toBuffer();

    if (output.length > AVATAR_OUTPUT_MAX_BYTES) {
      throw new AvatarInputError('Normalized avatar exceeds the safe output size.', 422);
    }
    const dataUrl = `${OUTPUT_PREFIX}${output.toString('base64')}`;
    if (dataUrl.length > AVATAR_DATA_URL_MAX_LENGTH) {
      throw new AvatarInputError('Normalized avatar data URL exceeds the safe output size.', 422);
    }
    return dataUrl;
  } catch (error) {
    if (error instanceof AvatarInputError) throw error;
    throw new AvatarInputError('Avatar is malformed, unsupported, or has unsafe dimensions.');
  }
}
