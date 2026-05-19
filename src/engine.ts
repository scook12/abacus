export type Scope = 'fs' | 'net' | 'tool' | 'skill' | 'secret';
export type CommonVerb = 'use' | 'read' | 'edit' | 'create' | 'delete' | '*';
export type NetVerb = 'get' | 'post' | 'put' | 'patch' | 'delete' | 'options' | 'head' | '*';

type ContextByScope = {
  fs: { type: 'fs', id: string, path: string };
  net: { type: 'net', id: string, url: string, host?: string, path?: string, scheme?: string, port?: string };
  tool: { type: 'tool', id: string, tool: string, argv0?: string, argv?: string[] };
  skill: { type: 'skill', id: string, skill: string };
  secret: { type: 'secret', id: string, secret: string };
}

type VerbByScope = {
  fs: CommonVerb;
  tool: CommonVerb;
  skill: CommonVerb;
  secret: CommonVerb;
  net: NetVerb;
}

export type Action<S extends Scope = Scope> =
  S extends Scope ? `${S}::${VerbByScope[S]}` : never;

type ScopeFromAction<A extends Action> =
  A extends `${infer S extends Scope}::${string}` ? S : never;

type Assert<T extends true> = T;

export type ActionTypeChecks = [
  Assert<'net::get' extends Action ? true : false>,
  Assert<'secret::read' extends Action ? true : false>,
  Assert<'net::use' extends Action ? false : true>,
  Assert<'secret::options' extends Action ? false : true>,
  Assert<'fs::post' extends Action ? false : true>
];


export type Decision = {
  policyVersion: string;
  effect: 'deny' | 'ask' | 'allow';
  reasons: string[];
}

export type Actor = {
  id: string;
  permissions: Record<string, Decision['effect']>;
}

export type Input<A extends Action = Action> = {
  requestId: string;
  timestamp: string; // ISO timestamp
  agent?: string;
  actor: Actor;
  action: A;
  context: ContextByScope[ScopeFromAction<A>]
}
