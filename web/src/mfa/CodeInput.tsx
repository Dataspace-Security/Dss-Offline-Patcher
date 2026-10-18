import { useEffect, useRef, type ClipboardEvent, type KeyboardEvent } from "react";
import "./mfa.css";

const LEN = 6;

/**
 * Six one-digit boxes for an authenticator code. Typing moves to the next
 * box, Backspace goes back, pasting "123 456" fills all six, and
 * `onComplete` fires once all six digits are present.
 */
export function CodeInput({ value, onChange, onComplete, disabled, autoFocus, invalid }: {
  value: string; onChange: (v: string) => void; onComplete?: (code: string) => void;
  disabled?: boolean; autoFocus?: boolean; invalid?: boolean;
}) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const digits = Array.from({ length: LEN }, (_, i) => value[i] ?? "");

  useEffect(() => {
    if (autoFocus) refs.current[Math.min(value.length, LEN - 1)]?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoFocus]);

  // Clearing the value (wrong code) puts the cursor back in the first box.
  useEffect(() => {
    if (value === "" && !disabled) refs.current[0]?.focus();
  }, [value, disabled]);

  const commit = (next: string, focusAt: number) => {
    const clean = next.replace(/\D/g, "").slice(0, LEN);
    onChange(clean);
    refs.current[Math.min(focusAt, LEN - 1)]?.focus();
    if (clean.length === LEN) onComplete?.(clean);
  };

  const setDigit = (i: number, raw: string) => {
    const d = raw.replace(/\D/g, "");
    if (!d) return;
    if (d.length > 1) { commit(value.slice(0, i) + d, i + d.length); return; } // autofill / fast typing
    const arr = [...digits];
    arr[i] = d;
    commit(arr.join(""), i + 1);
  };

  const onKey = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace") {
      e.preventDefault();
      const at = digits[i] ? i : Math.max(0, i - 1);
      const arr = [...digits];
      arr[at] = "";
      onChange(arr.join("").slice(0, at) + arr.slice(at + 1).join(""));
      refs.current[at]?.focus();
    } else if (e.key === "ArrowLeft" && i > 0) {
      e.preventDefault();
      refs.current[i - 1]?.focus();
    } else if (e.key === "ArrowRight" && i < LEN - 1) {
      e.preventDefault();
      refs.current[i + 1]?.focus();
    }
  };

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData.getData("text").replace(/\D/g, "");
    if (!text) return;
    e.preventDefault();
    commit(text, text.length);
  };

  return (
    <div className="code-input" role="group" aria-label="6-digit code">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => { refs.current[i] = el; }}
          className={`code-digit ${invalid ? "code-digit-bad" : ""}`}
          value={d}
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          pattern="[0-9]*"
          maxLength={i === 0 ? LEN : 1}
          aria-label={`Digit ${i + 1}`}
          aria-invalid={invalid || undefined}
          disabled={disabled}
          onChange={(e) => setDigit(i, e.target.value)}
          onKeyDown={(e) => onKey(i, e)}
          onPaste={onPaste}
          onFocus={(e) => e.currentTarget.select()}
        />
      ))}
    </div>
  );
}
