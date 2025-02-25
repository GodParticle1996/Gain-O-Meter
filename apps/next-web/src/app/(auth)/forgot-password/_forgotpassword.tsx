"use client";
import { useState } from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { ArrowRight, MailCheckIcon, Loader, ArrowLeft } from "lucide-react";
import { useSearchParams } from "next/navigation";

import {
    Form,
    FormControl,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import Logo from "@/components/logo";
import { forgotPasswordMutationFn } from "@/lib/api";
import { useMutation } from "@tanstack/react-query";
import { toast } from "@/hooks/use-toast";
import Link from "next/link";

export default function ForgotPassword() {
    const params = useSearchParams();

    const email = params.get("email");

    const [isSubmitted, setIsSubmitted] = useState(false);

    const { mutate, isPending } = useMutation({
        mutationFn: forgotPasswordMutationFn,
    });

    const formSchema = z.object({
        email: z.string().trim().email().min(1, {
            message: "Email is required",
        }),
    });

    const form = useForm<z.infer<typeof formSchema>>({
        resolver: zodResolver(formSchema),
        defaultValues: {
            email: email || "",
        },
    });

    const onSubmit = (values: z.infer<typeof formSchema>) => {
        mutate(values, {
            onSuccess: (response: any) => {
                setIsSubmitted(true);
            },
            onError: (error) => {
                console.log(error);
                toast({
                    title: "Error",
                    description: error.message,
                    variant: "destructive",
                });
            },
        });
    };

    return (
        <main className="w-full min-h-[590px] h-full max-w-full flex items-center justify-center ">
            {!isSubmitted ? (
                <div className="w-full h-full p-5 rounded-md">
                    <Logo />

                    <h1
                        className="text-xl tracking-[-0.16px] dark:text-[#fcfdffef] font-bold mb-1.5 mt-8
        text-center sm:text-left"
                    >
                        Reset Password
                    </h1>
                    <p className="mb-6 text-center sm:text-left text-base dark:text-[#f1f7feb5] font-normal">
                        Include your registered email address and we'll
                        send you an email with instructions to reset your password.
                    </p>
                    <Form {...form}>
                        <form
                            className="flex flex-col gap-6"
                            onSubmit={form.handleSubmit(onSubmit)}
                        >
                            <div className="mb-0">
                                <FormField
                                    control={form.control}
                                    name="email"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel className="dark:text-[#f1f7feb5] text-sm">
                                                Email
                                            </FormLabel>
                                            <FormControl>
                                                <Input
                                                    placeholder="subscribeto@gainometer.com"
                                                    autoComplete="off"
                                                    {...field}
                                                />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            </div>
                            <Button
                                disabled={isPending}
                                className="w-full text-[15px] h-[40px] text-white font-semibold hover:bg-primary-hover"
                            >
                                {isPending && <Loader className="animate-spin" />}
                                Send Reset Details
                            </Button>
                        </form>
                    </Form>
                </div>
            ) : (
                <div className="w-full h-[80vh] flex flex-col gap-2 items-center justify-center rounded-md">
                    <div className="size-[48px]">
                        <MailCheckIcon size="48px" className="animate-bounce" />
                    </div>
                    <h2 className="text-xl tracking-[-0.16px] dark:text-[#fcfdffef] font-bold">
                        Check your email
                    </h2>
                    <p className="mb-2 text-center text-sm text-muted-foreground dark:text-[#f1f7feb5] font-normal">
                        We just sent a password reset link to {form.getValues().email}.
                    </p>
                    <Link href="/">
                        <Button
                            className="w-full text-[15px] h-[40px] text-white font-semibold hover:bg-primary-hover"
                            disabled={isPending}
                            type="submit"
                        >
                            {isPending && <Loader className="animate-spin" />}
                            <ArrowLeft />
                            Login
                        </Button>
                    </Link>
                </div>
            )}
        </main>
    );
}
