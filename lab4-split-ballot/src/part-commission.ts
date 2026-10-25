import { verify } from "./rsa.ts";
import {
  serializePart,
  type BallotPart,
  type PartCommissionLabel,
  type PartMessage,
  type VkRejection,
  type VkResult,
  type VoterRecord,
} from "./types.ts";

export type VkCheck = "inList" | "signature" | "notVotedYet";
export type VkEvent = {
  readonly commission: PartCommissionLabel;
  readonly check: VkCheck;
  readonly passed: boolean;
  readonly detail: string;
};

/**
 * ВК-1 / ВК-2: отримує від ЦВК список виборців, приймає одну зашифровану частину
 * бюлетеня від кожного виборця, перевіряє його та ЕЦП, а після голосування публікує
 * пари «ID виборця — зашифрована частина». Закритого ключа ЦВК ця комісія не має.
 */
export class PartCommission {
  readonly label: PartCommissionLabel;

  private voters = new Map<string, VoterRecord>();
  private readonly received = new Map<string, BallotPart>();
  private readonly observer: ((event: VkEvent) => void) | undefined;

  constructor(label: PartCommissionLabel, observer?: (event: VkEvent) => void) {
    this.label = label;
    this.observer = observer;
  }

  /** Крок 1: прийом від ЦВК списку виборців з відкритими ключами ЕЦП. */
  loadVoterList(list: readonly VoterRecord[]): void {
    this.voters = new Map(list.map((record) => [record.name, record]));
  }

  /** Крок 4: перевірка виборця за списком, перевірка ЕЦП, відмітка про отримання. */
  receive(message: PartMessage): VkResult {
    const { senderName, part } = message;

    const voter = this.voters.get(senderName);
    this.note("inList", voter !== undefined, voter ? `«${senderName}» є у списку від ЦВК` : `«${senderName}» відсутній у списку`);
    if (!voter) return this.reject(senderName, "NOT_IN_LIST");

    const signatureValid = verify(serializePart(part), part.signature, voter.publicKey);
    this.note("signature", signatureValid, signatureValid ? "H = H_c, ЕЦП справжній" : "H ≠ H_c, ЕЦП недійсний");
    if (!signatureValid) return this.reject(senderName, "BAD_SIGNATURE");

    const alreadyVoted = this.received.has(senderName);
    this.note(
      "notVotedYet",
      !alreadyVoted,
      alreadyVoted ? `від «${senderName}» частину вже прийнято` : "відмітку про отримання поставлено",
    );
    if (alreadyVoted) return this.reject(senderName, "ALREADY_VOTED");

    this.received.set(senderName, { voterId: part.voterId, encryptedPart: part.encryptedPart });
    return { status: "accepted", voterName: senderName, voterId: part.voterId };
  }

  /** Крок 5: публікація всіх ID і відповідних зашифрованих частин (без ПІБ). */
  publish(): BallotPart[] {
    return [...this.received.values()];
  }

  private note(check: VkCheck, passed: boolean, detail: string): void {
    this.observer?.({ commission: this.label, check, passed, detail });
  }

  private reject(voterName: string, reason: VkRejection): VkResult {
    return { status: "rejected", voterName, reason };
  }
}
