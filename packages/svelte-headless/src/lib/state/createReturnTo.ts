import { createStorage } from "./storage.svelte";

export type ReturnToOptions = {
  id: string;
  goto: (path: string) => Promise<void>;
  defaultPath?: string;
};

export function createReturnTo({ id, goto, defaultPath }: ReturnToOptions) {
  const returnTo = createStorage<string | null>(`return-to:${id}`, null);

  function setURL(url: URL) {
    returnTo.item = `${url.pathname}${url.search}${url.hash}`;
  }

  function setPath(path: string) {
    setURL(new URL(path, location.href));
  }

  async function onReturn() {
    const path = returnTo.item;
    const returnToPath = path && /^\/(?![/\\])/.test(path) ? path : defaultPath;
    returnTo.item = null;

    if (returnToPath) {
      try {
        await goto(returnToPath);
      } catch (error) {
        returnTo.item = returnToPath;
        throw error;
      }
    }
  }

  return {
    setURL,
    setPath,
    onReturn,
  };
}
