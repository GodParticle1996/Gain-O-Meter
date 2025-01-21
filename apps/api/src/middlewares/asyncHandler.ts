import { NextFunction, Request, Response } from "express";

type AsynControllerType = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<any>;

export const asyncHandler =
  (controller: AsynControllerType): AsynControllerType =>
  async (req, res, next) => {
    try {
      await controller(req, res, next);
    } catch (error) {
      next(error);
    }
  };

/*** The above code is a TypeScript function that takes in a controller function as an argument and returns a new function that wraps the original controller function. 
The new function catches any errors that occur during the execution of the original controller function and passes them to the next middleware function in the Express.js 
middleware chain. The below is the code in more readable format: 

// Define the type for asynchronous controller functions
type AsyncControllerType = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<any>;

// Create an asyncHandler function to wrap controllers with error handling
export function asyncHandler(
  controller: AsyncControllerType
): AsyncControllerType {
  // Create a wrapper function that Express can use as middleware
  const middlewareWrapper: AsyncControllerType = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    try {
      // Call the controller function and wait for it to complete
      await controller(req, res, next);
    } catch (error) {
      // If an error occurs, pass it to the next error-handling middleware
      next(error);
    }
  };

  // Return the wrapper function to be used as middleware
  return middlewareWrapper;
}
***/
