"""
Module 4 — LangGraph Agentic Reasoning Loop

Handles non-deterministic vulnerability conditions using a cyclic
ReAct-style agent. The agent is equipped with code analysis tools
and terminates when it has enough evidence to evaluate all blueprint conditions.

Graph structure:
  START → agent_node → [tool_node] → agent_node → ... → END

The agent is given the blueprint as its objective and iterates until
it either:
  a) Has evaluated all required conditions, OR
  b) Reaches the max_iterations limit
"""

import logging
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from api.config import settings
from schemas.blueprint import AttackBlueprint
from schemas.report import ConditionResult, VerificationMethod

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 15

AGENT_SYSTEM_PROMPT = """You are a senior security analyst performing a context-aware vulnerability assessment.

You have been given an Attack Blueprint describing a CVE's exploitation conditions.
Your job is to use the available tools to investigate whether those conditions are met
in the target codebase, and report your findings.

## Your investigation objectives:
1. Check if the vulnerable package/module is imported
2. Verify if the vulnerable symbol is actually called
3. Trace the call chain to see if untrusted input can reach the vulnerable code
4. Look for any mitigations (input validation, type checks, permission guards)
5. Consider the deployment context clues in the blueprint

## Output format:
When you are done investigating, output a JSON object in this exact format:
```json
{
  "reachability_verified": true/false,
  "execution_trace": "step-by-step trace description",
  "conditions_met": [
    {"condition": "...", "result": true/false, "evidence": "..."}
  ],
  "environmental_mitigations": "description or 'None identified'",
  "confidence_score": 0.0-1.0,
  "summary": "one paragraph explanation"
}
```

Use tools iteratively. Start broad (find_all_callers, get_import_chain),
then zoom in (get_function_body, read_file_slice).
"""


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    blueprint: dict
    iteration_count: int


class AgentReasoningLoop:
    """
    LangGraph agent for evaluating non-deterministic blueprint conditions.
    """

    def __init__(self):
        self._graph = None

    def _build_graph(self, tools: list) -> Any:
        llm = ChatOpenAI(
            model=settings.llmas_model,
            base_url=settings.llmas_base_url,
            api_key=settings.llmas_api_key,
            temperature=0,
        )
        llm_with_tools = llm.bind_tools(tools)

        def agent_node(state: AgentState):
            if state["iteration_count"] >= MAX_ITERATIONS:
                return {"messages": [AIMessage(content="MAX_ITERATIONS_REACHED")]}
            response = llm_with_tools.invoke(state["messages"])
            return {
                "messages": [response],
                "iteration_count": state["iteration_count"] + 1,
            }

        def should_continue(state: AgentState):
            last = state["messages"][-1]
            if isinstance(last, AIMessage):
                if last.tool_calls:
                    return "tools"
                return END
            return END

        tool_node = ToolNode(tools)

        graph = StateGraph(AgentState)
        graph.add_node("agent", agent_node)
        graph.add_node("tools", tool_node)
        graph.add_edge(START, "agent")
        graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
        graph.add_edge("tools", "agent")

        return graph.compile()

    async def run(
        self,
        blueprint: AttackBlueprint,
        codebase_path: Path,
        code_index,
    ) -> list[ConditionResult]:
        from modules.agent.tools import file_search, ast_slicer, cross_ref

        file_search.set_codebase_root(codebase_path)
        ast_slicer.set_codebase_root(codebase_path)
        cross_ref.set_codebase_root(codebase_path)
        cross_ref.set_code_index(code_index)

        tools = [
            file_search.search_files_by_name,
            file_search.read_file_slice,
            file_search.search_content,
            ast_slicer.get_function_body,
            ast_slicer.list_functions_in_file,
            cross_ref.find_all_callers,
            cross_ref.find_definition,
            cross_ref.get_import_chain,
        ]

        compiled_graph = self._build_graph(tools)

        user_message = self._format_user_message(blueprint)
        initial_state = {
            "messages": [
                SystemMessage(content=AGENT_SYSTEM_PROMPT),
                HumanMessage(content=user_message),
            ],
            "blueprint": blueprint.model_dump(),
            "iteration_count": 0,
        }

        logger.info("Starting agent loop for %s (max %d iterations)", blueprint.cve_id, MAX_ITERATIONS)
        final_state = await compiled_graph.ainvoke(initial_state)

        return self._parse_results(final_state["messages"])

    def _format_user_message(self, blueprint: AttackBlueprint) -> str:
        c = blueprint.required_conditions.code_level
        e = blueprint.required_conditions.environment_level
        return f"""
Investigate the following vulnerability in the target codebase:

CVE: {blueprint.cve_id}
CWE: {blueprint.cwe_id or 'N/A'}

Vulnerable Symbol: {c.vulnerable_symbol}
Package Context: {c.package_context}
Expected Data Flow: {c.expected_data_flow}
Indicators of Reachability: {', '.join(c.indicators_of_reachability)}

Environment Constraints:
- Network Exposure: {e.network_exposure or 'Unknown'}
- Required Feature Flags: {', '.join(e.required_feature_flags) or 'None'}
- Runtime Constraints: {e.runtime_version_constraints or 'None'}

Exploitation Mechanism:
{blueprint.exploitation_mechanism.step_by_step}

Begin your investigation now.
""".strip()

    def _parse_results(self, messages: list) -> list[ConditionResult]:
        """
        Extracts ConditionResult objects from the agent's final message.
        Falls back to a single summarized result if structured parsing fails.
        """
        import json, re

        for msg in reversed(messages):
            if isinstance(msg, AIMessage) and msg.content:
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                match = re.search(r"```json\s*(\{.*?\})\s*```", content, re.DOTALL)
                if match:
                    try:
                        data = json.loads(match.group(1))
                        results = []
                        for cond in data.get("conditions_met", []):
                            results.append(ConditionResult(
                                condition_description=cond.get("condition", "Agent condition"),
                                result=bool(cond.get("result", False)),
                                evidence=cond.get("evidence", ""),
                                method=VerificationMethod.AGENT_LLM,
                            ))
                        if not results:
                            results.append(ConditionResult(
                                condition_description="Agent overall assessment",
                                result=bool(data.get("reachability_verified", False)),
                                evidence=data.get("execution_trace", data.get("summary", "")),
                                method=VerificationMethod.AGENT_LLM,
                            ))
                        return results
                    except (json.JSONDecodeError, KeyError):
                        pass

                return [ConditionResult(
                    condition_description="Agent assessment (unstructured)",
                    result=False,
                    evidence=content[:500],
                    method=VerificationMethod.AGENT_LLM,
                )]

        return [ConditionResult(
            condition_description="Agent did not produce a result",
            result=False,
            evidence="No terminal message from agent",
            method=VerificationMethod.AGENT_LLM,
        )]
