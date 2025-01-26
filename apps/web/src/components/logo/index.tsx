import Link from "next/link";
import React from "react";

const Logo = (props: { url?: string; size?: string; fontSize?: string }) => {
    const { url = "/", size = "50px", fontSize = "24px" } = props;
    return (
        <div className="flex items-center justify-center sm:justify-start">
            <Link
                href={url}
                className="rounded-lg flex items-center justify-center border-2 dark:border-gray-200 bg-gradient-to-br from-rose-400 to-rose-700 to-90%"
                style={{ width: size, height: size }}
            >
                <svg
                    className="w-14 h-14 text-pink-300"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                >
                    <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth="2"
                        d="M13 10V3L4 14h7v7l9-11h-7z"
                    />
                </svg>
            </Link>
        </div>
    );
};

export default Logo;