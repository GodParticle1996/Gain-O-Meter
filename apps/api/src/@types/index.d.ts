import { UserDocument } from "../database/models/user.model";
import { Request } from "express";

declare global {
  namespace Express {
    interface User extends UserDocument {}
    interface Request {
      sessionId?: string;
    }
  }
}

/*
NOTE:The above code is a TypeScript declaration file that extends the Express namespace to include two new interfaces:
1. Using declare global to modify TypeScript's global scope
2. Extending the existing Express namespace
3. Adding two interface declarations:
4. Extends the User interface with UserDocument properties
5. Adds a new sessionId property to Express's Request interface

The magic happens because:
1. TypeScript automatically merges these declarations with the existing Express types
2. When you use req.user or req.sessionId anywhere in your codebase, TypeScript knows about these properties
3. You don't need to explicitly import these types - they're available globally
4. This is why req.user?.id works in session.controller.ts without additional imports
5. This pattern is commonly used to augment existing libraries' type definitions with custom properties your application needs.

Creating a userReducer for React state management with a Global typescript interface
declare global {
  interface GlobalReducerEvent {
    LOG_IN: {
        username: string
    }
  }
}

export type GlobalReducer<TState> = (
  state: TState,
  event: {
    [EventType in keyof GlobalReducerEvent]: {
      type: EventType
    } & GlobalReducerEvent[EventType]
  }[keyof GlobalReducerEvent]
) => TState

export const userReducer: GlobalReducer<{ id: string }> = (
  state,
  event
) => {
event
  return state
}

declare global {
  interface GlobalReducerEvent {
    LOG_IN: { userId: string }; 
  }
}

export const userReducer: GlobalReducer<{ id: string; name?: string }> = (
  state,
  event
) => {
  if (event.type === 'LOG_IN') {
    return { ...state, id: event.userId, name: 'Guest' }; // Use event.userId
  }
  return state;
};
*/
