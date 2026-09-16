import type { Capability } from "./types.js";

/** Exact capability/resource identity shared by the independent grant stores. */
export function capabilityKey(capability: Capability): string {
  return capability.kind + "\u0000" + capability.resource;
}
