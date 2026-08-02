import { MessagesAnnotation, StateGraph } from "@langchain/langgraph";
import { createAgent } from "langchain";

import {
  LatchClient,
  createLatchAgentMiddleware,
  createLatchToolNode,
} from "../dist/index.js";

async function verifyPublicTypes(): Promise<void> {
  const latch = new LatchClient("http://127.0.0.1:7070");
  const middleware = await createLatchAgentMiddleware(latch);
  createAgent({ model: "provider:model", tools: [], middleware: [middleware] });

  const toolNode = await createLatchToolNode([], latch);
  new StateGraph(MessagesAnnotation).addNode("tools", toolNode);
}

void verifyPublicTypes;
