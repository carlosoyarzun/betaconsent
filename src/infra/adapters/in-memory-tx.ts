// Gobierna: CA-124, diseño postgres-design.md rev. 2 §5 ("In-memory: snapshot de los Maps y
// restauración si falla"). Infraestructura compartida de los adaptadores in-memory IT0 para dar
// semántica todo-o-nada a `UnitOfWorkPort.inTenant`.
//
// Mecanismo: escritura directa + journal de deshacer. Mientras hay una unidad de trabajo
// activa, cada mutación de un `JournaledMap` (o de una `JournaledList`) apila la operación
// inversa; al fallar, el UoW la deshace en orden inverso. Se eligió journal en vez de snapshot
// completo porque deshace SOLO lo escrito dentro de la unidad de trabajo (una escritura de otro
// flujo fuera del UoW en otra clave no se pisa). Sin PII, sin red.

export type Undo = () => void;

/** Método (con clave símbolo) por el que el UoW asigna el journal activo, o null al terminar. */
export const TX_JOURNAL = Symbol("consent.inMemory.txJournal");

/** Lookup sin tenant por hash de secreto, solo para el TenantResolverPort in-memory. */
export const UNSCOPED_LOOKUP = Symbol("consent.inMemory.unscopedLookup");

export interface TxParticipant {
  [TX_JOURNAL](journal: Undo[] | null): void;
}

export function isTxParticipant(value: unknown): value is TxParticipant {
  return typeof value === "object" && value !== null && typeof (value as Partial<TxParticipant>)[TX_JOURNAL] === "function";
}

export interface UnscopedTokenLookup<R> {
  [UNSCOPED_LOOKUP](tokenHash: string): R | null;
}

export function hasUnscopedLookup<R>(value: unknown): value is UnscopedTokenLookup<R> {
  return typeof value === "object" && value !== null && typeof (value as Partial<UnscopedTokenLookup<R>>)[UNSCOPED_LOOKUP] === "function";
}

export class JournaledMap<K, V> extends Map<K, V> {
  journal: Undo[] | null = null;

  override set(key: K, value: V): this {
    const journal = this.journal;
    if (journal) {
      const had = super.has(key);
      const previous = super.get(key) as V;
      journal.push(() => {
        if (had) super.set(key, previous);
        else super.delete(key);
      });
    }
    return super.set(key, value);
  }

  override delete(key: K): boolean {
    const journal = this.journal;
    if (journal && super.has(key)) {
      const previous = super.get(key) as V;
      journal.push(() => {
        super.set(key, previous);
      });
    }
    return super.delete(key);
  }

  override clear(): void {
    const journal = this.journal;
    if (journal) {
      const snapshot = [...super.entries()];
      journal.push(() => {
        for (const [key, value] of snapshot) super.set(key, value);
      });
    }
    super.clear();
  }
}

/** Lista append-only journaled (ledger, outbox): el undo de un push es quitar el último. */
export class JournaledList<T> {
  readonly items: T[] = [];
  journal: Undo[] | null = null;

  push(item: T): void {
    this.items.push(item);
    this.journal?.push(() => {
      this.items.pop();
    });
  }
}
