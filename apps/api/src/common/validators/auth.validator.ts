import { z } from "zod";

export const emailSchema = z.string().trim().email().min(1).max(255);
export const passwordSchema = z.string().trim().min(6).max(255);
export const verificationCodeSchema = z.string().trim().min(1).max(25);

export const registerSchema = z
  .object({
    name: z.string().trim().min(1).max(255),
    email: emailSchema,
    password: passwordSchema,
    confirmPassword: passwordSchema,
  })
  .refine((val) => val.password === val.confirmPassword, {
    message: "Password does not match",
    path: ["confirmPassword"],
  });

export const loginSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  userAgent: z.string().optional(),
});

export const verificationEmailSchema = z.object({
  code: verificationCodeSchema,
});

export const resetPasswordSchema = z.object({
  password: passwordSchema,
  verificationCode: verificationCodeSchema,
});

/*
{ ...req.body }: This creates a new object using the spread syntax. It copies all the properties from req.body into this new object. This is often done to avoid 
directly modifying the original req.body.

registerSchema.parse(...): This is where the magic of Zod happens. You're passing the newly created object (containing the request data) to the parse method of 
your Zod schema. If the data in the request body meets the validation rules defined in registerSchema, the parse method will return the validated data. If the data 
doesn't meet the rules, Zod will throw an error.

Success: If all the validation rules pass, registerSchema.parse() returns a JavaScript object containing the parsed and validated data. This object is assigned to the body variable. This body object is now safe to use in your application because you've confirmed it meets your requirements.
Failure: If any validation rule fails, Zod throws an error (a ZodError). This error will contain details about which fields failed validation and why. You'll typically want to catch this error and send an appropriate error response to the client.
*/
