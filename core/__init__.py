"""
SCA risk assessment core.

One flat package, one concept per module:

    config.py     settings, and the generator for every file that mirrors them
    errors.py     typed failures
    models.py     every data shape
    store.py      blueprint lookup
    joern.py      the only code that talks to Joern
    llm.py        the only code that talks to the model / MCP
    agent.py      the one agent loop
    probes.py     the four evidence questions
    policy.py     the only code that decides activation and exploitability
    scoring.py    CVSS environmental scoring
    pipeline.py   wiring, and the only entry point callers need

The pipeline is agent-only on purpose: evidence comes from an LLM with tools,
never from a parallel deterministic implementation. Unavailability raises
(see errors.py) instead of degrading.

Start here:

    from core.pipeline import assess

Nothing is imported at package level, so `python -m core.config` and the like
stay cheap and free of import cycles.
"""
