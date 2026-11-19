/**
 * EIP-712 / EIP-3009 `TransferWithAuthorization` verification for x402 `exact` payments in USDC.
 *
 * The payer signs a typed-data message that lets anyone submit the transfer to the USDC contract. This module
 * rebuilds that message, recovers the signer with secp256k1 and checks it matches `authorization.from`.
 * Smart-contract wallet signatures (EIP-1271 / ERC-6492, longer than 65 bytes) cannot be checked offline and are
 * left to the upstream facilitator.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

export interface UsdcDomain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

/** USDC on the networks the clearinghouse accepts. Name and version are the token's own EIP-712 domain. */
export const USDC_DOMAINS: Record<string, UsdcDomain> = {
  'eip155:8453': {
    name: 'USD Coin',
    version: '2',
    chainId: 8453,
    verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  },
  'eip155:84532': {
    name: 'USDC',
    version: '2',
    chainId: 84532,
    verifyingContract: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
  },
};

export interface Eip3009Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

const enc = new TextEncoder();
const keccakText = (s: string): Uint8Array => keccak_256(enc.encode(s));

const DOMAIN_TYPEHASH = keccakText(
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)',
);
const TRANSFER_TYPEHASH = keccakText(
  'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)',
);

function hexToBytes(hex: string): Uint8Array | null {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    return null;
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function word(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
}

function uint256(value: string | number | bigint): Uint8Array | null {
  let n: bigint;
  try {
    n = BigInt(value);
  } catch {
    return null;
  }
  if (n < 0n || n >= 1n << 256n) {
    return null;
  }
  return hexToBytes(n.toString(16).padStart(64, '0'));
}

function address(value: string): Uint8Array | null {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    return null;
  }
  return word(hexToBytes(value) as Uint8Array);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** The 32-byte digest the payer signed, or null when a field is malformed. */
export function transferWithAuthorizationDigest(
  domain: UsdcDomain,
  auth: Eip3009Authorization,
): Uint8Array | null {
  const chainId = uint256(domain.chainId);
  const contract = address(domain.verifyingContract);
  const from = address(auth.from);
  const to = address(auth.to);
  const value = uint256(auth.value);
  const validAfter = uint256(auth.validAfter);
  const validBefore = uint256(auth.validBefore);
  const nonce = /^0x[0-9a-fA-F]{64}$/.test(auth.nonce) ? hexToBytes(auth.nonce) : null;
  if (!chainId || !contract || !from || !to || !value || !validAfter || !validBefore || !nonce) {
    return null;
  }
  const domainSeparator = keccak_256(
    concat([DOMAIN_TYPEHASH, keccakText(domain.name), keccakText(domain.version), chainId, contract]),
  );
  const structHash = keccak_256(
    concat([TRANSFER_TYPEHASH, from, to, value, validAfter, validBefore, nonce]),
  );
  return keccak_256(concat([new Uint8Array([0x19, 0x01]), domainSeparator, structHash]));
}

/** Checksum-free lowercase address of the signer of `digest`, or null. Rejects high-s signatures like USDC does. */
export function recoverSigner(digest: Uint8Array, signatureHex: string): string | null {
  const sig = hexToBytes(signatureHex);
  if (!sig || sig.length !== 65) {
    return null;
  }
  let v = sig[64] as number;
  if (v >= 27) {
    v -= 27;
  }
  if (v !== 0 && v !== 1) {
    return null;
  }
  try {
    const parsed = secp256k1.Signature.fromCompact(sig.slice(0, 64));
    if (parsed.hasHighS()) {
      return null;
    }
    const point = parsed.addRecoveryBit(v).recoverPublicKey(digest);
    const pub = point.toRawBytes(false).slice(1);
    return `0x${bytesToHex(keccak_256(pub).slice(-20))}`;
  } catch {
    return null;
  }
}

export type Eip3009Check =
  | { ok: true }
  | {
      ok: false;
      reason:
        | 'unsupported_network'
        | 'asset_mismatch'
        | 'malformed_authorization'
        | 'smart_wallet_signature_needs_facilitator'
        | 'malformed_evm_signature'
        | 'signature_mismatch';
    };

/** Verify an x402 `exact` EIP-3009 payment offline. */
export function verifyEip3009(
  network: string,
  asset: string,
  auth: Eip3009Authorization,
  signatureHex: string,
): Eip3009Check {
  const domain = USDC_DOMAINS[network];
  if (!domain) {
    return { ok: false, reason: 'unsupported_network' };
  }
  if (asset.toLowerCase() !== domain.verifyingContract.toLowerCase()) {
    return { ok: false, reason: 'asset_mismatch' };
  }
  const digest = transferWithAuthorizationDigest(domain, auth);
  if (!digest) {
    return { ok: false, reason: 'malformed_authorization' };
  }
  const sigBytes = hexToBytes(signatureHex);
  if (!sigBytes) {
    return { ok: false, reason: 'malformed_evm_signature' };
  }
  if (sigBytes.length > 65) {
    return { ok: false, reason: 'smart_wallet_signature_needs_facilitator' };
  }
  const signer = recoverSigner(digest, signatureHex);
  if (!signer) {
    return { ok: false, reason: 'malformed_evm_signature' };
  }
  return signer === auth.from.toLowerCase() ? { ok: true } : { ok: false, reason: 'signature_mismatch' };
}
