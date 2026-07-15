import { inject, type InjectionKey } from "vue";

export type ConfirmOptions = {
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
};

export type Confirm = (options: ConfirmOptions) => Promise<boolean>;

export const ConfirmKey: InjectionKey<Confirm> = Symbol("HunterConfirm");

export function useConfirm(): Confirm {
  const confirm = inject(ConfirmKey);
  if (confirm === undefined) throw new Error("Confirm service is unavailable");
  return confirm;
}
