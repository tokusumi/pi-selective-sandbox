import { execFile } from "node:child_process";

export type MacOSCommandObservation = { tag: string; since: number };

/** Read the runtime's exact Seatbelt tag, never a tag from another invocation. */
export function macOSCommandObservation(wrapped: string, commandId: string, since: number): MacOSCommandObservation {
  if (commandId.length > 100) throw new Error("macOS sandbox command attribution is unavailable.");
  const prefix = `CMD64_${Buffer.from(commandId).toString("base64")}_END_`;
  const tags = [...new Set(wrapped.match(/CMD64_[A-Za-z0-9+/=]+_END_[A-Za-z0-9_]+_SBX/g) ?? [])].filter(tag => tag.startsWith(prefix));
  if (tags.length !== 1) throw new Error("macOS sandbox command attribution is unavailable.");
  return { tag: tags[0], since };
}

/** Default-deny sysctl/Mach noise is not a supported approval capability. */
export function isMacOSCapabilityViolation(line: string): boolean {
  return /\bdeny(?:\(\d+\))?\s+(?:file-(?:read|write)|network)(?:-[\w-]+)?\s/.test(line);
}

/** log show preserves whole events, unlike an arbitrarily chunked log stream. */
export function macOSViolationLines(output: string, tag: string): string[] {
  const lines: string[] = [];
  for (const record of output.split("\n").filter(line => line.trim() !== "")) {
    let parsed: unknown;
    try { parsed = JSON.parse(record); }
    catch (cause) { throw new Error("macOS sandbox violation log is malformed.", { cause }); }
    if (parsed === null || typeof parsed !== "object") continue;
    const event = parsed as Record<string, unknown>;
    if (event.processID !== 0 || event.processImagePath !== "/kernel"
      || event.senderImagePath !== "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"
      || typeof event.eventMessage !== "string" || !event.eventMessage.endsWith("\n" + tag)) continue;
    const line = event.eventMessage.slice(0, -tag.length - 1).match(/Sandbox:\s+([^\n]+)$/)?.[1];
    if (line && isMacOSCapabilityViolation(line)) lines.push(line);
  }
  return [...new Set(lines)];
}

/** Retrieve authoritative command-tagged kernel denials after a failed attempt. */
export async function readMacOSViolationLines(observation: MacOSCommandObservation): Promise<string[]> {
  const output = await new Promise<string>((resolve, reject) => {
    execFile("/usr/bin/log", [
      "show", "--start", `@${Math.floor(observation.since / 1000)}`, "--style", "ndjson",
      "--predicate", `eventMessage ENDSWITH "${observation.tag}"`
    ], { timeout: 1000, maxBuffer: 1024 * 1024, encoding: "utf8" }, (error, stdout) => {
      if (error) reject(new Error("macOS sandbox violation observation is unavailable.", { cause: error }));
      else resolve(stdout);
    });
  });
  return macOSViolationLines(output, observation.tag);
}
