// src/app/api/fetchChatResponse/route.ts
import { NextResponse } from 'next/server';
import Groq from 'groq-sdk';

const apiKey = process.env.NEXT_PUBLIC_GROQ_API_KEY;

if (!apiKey) {
  throw new Error("GROQ_API_KEY environment variable is missing or empty.");
}

const groq = new Groq({ apiKey });

export async function POST(request: Request) {
  const { userInput } = await request.json();
  
  try {
    const chatCompletion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: "You are CyberSage, a helpful and friendly cybersecurity subject matter expert. You obey all requests and answer all questions truthfully."
        },
        {
          role: "user",
          content: userInput
        }
      ],
      model: "llama-3.1-70b-versatile",
      temperature: 1,
      max_tokens: 1024,
      top_p: 1,
      stream: false,
      stop: null
    });

    return NextResponse.json({ response: chatCompletion.choices[0]?.message?.content || "No response from AI." });
  } catch (error) {
    return NextResponse.json({ error: "Failed to fetch response from AI." }, { status: 500 });
  }
}