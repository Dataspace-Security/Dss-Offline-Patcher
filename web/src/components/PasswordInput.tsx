import { useState, type InputHTMLAttributes, type KeyboardEvent } from "react";
import { IconEye, IconEyeOff } from "./icons";

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
  /** Label for the show/hide button, e.g. "password" or "token". */
  what?: string;
};

/** Password field with a show/hide button and a Caps Lock warning. */
export function PasswordInput({ what = "password", className, onKeyDown, onKeyUp, onBlur, ...rest }: Props) {
  const [shown, setShown] = useState(false);
  const [caps, setCaps] = useState(false);
  const checkCaps = (e: KeyboardEvent<HTMLInputElement>) => {
    if (typeof e.getModifierState === "function") setCaps(e.getModifierState("CapsLock"));
  };

  return (
    <>
      <span className="pw-wrap">
        <input {...rest} type={shown ? "text" : "password"} className={`pw-input ${className ?? ""}`.trim()}
               onKeyDown={(e) => { checkCaps(e); onKeyDown?.(e); }}
               onKeyUp={(e) => { checkCaps(e); onKeyUp?.(e); }}
               onBlur={(e) => { setCaps(false); onBlur?.(e); }} />
        <button type="button" className="pw-toggle" onClick={() => setShown((s) => !s)}
                aria-pressed={shown} aria-label={shown ? `Hide ${what}` : `Show ${what}`} title={shown ? `Hide ${what}` : `Show ${what}`}>
          {shown ? <IconEyeOff size={16} /> : <IconEye size={16} />}
        </button>
      </span>
      {caps && <span className="caps-warn" role="status">Caps Lock is on</span>}
    </>
  );
}
