/**
 * Ambient type definitions for Chrome Extension APIs in AntiDrain Companion.
 */

declare namespace chrome.runtime {
  interface Port {
    name: string;
    onDisconnect: {
      addListener(callback: (port: Port) => void): void;
    };
    onMessage: {
      addListener(callback: (message: unknown, port: Port) => void): void;
    };
    postMessage(message: unknown): void;
    disconnect(): void;
  }

  interface MessageSender {
    id?: string;
    tab?: {
      id?: number;
      url?: string;
      title?: string;
    };
    frameId?: number;
    url?: string;
    origin?: string;
  }

  const id: string;

  function connectNative(application: string): Port;
  function getURL(path: string): string;

  function sendMessage(message: unknown): Promise<any>;
  function sendMessage(message: unknown, responseCallback: (response: any) => void): void;

  const onMessage: {
    addListener(
      callback: (
        message: any,
        sender: MessageSender,
        sendResponse: (response?: any) => void
      ) => boolean | void | Promise<any>
    ): void;
  };
}

declare namespace chrome.storage {
  interface StorageArea {
    get(keys?: string | string[] | Record<string, any> | null): Promise<Record<string, any>>;
    set(items: Record<string, any>): Promise<void>;
    remove(keys: string | string[]): Promise<void>;
    clear(): Promise<void>;
  }

  const local: StorageArea;
  const session: StorageArea;
}
