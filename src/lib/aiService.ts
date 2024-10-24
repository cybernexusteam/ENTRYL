import Groq from 'groq-sdk';

const apiKey = process.env.NEXT_PUBLIC_GROQ_API_KEY;

if (!apiKey) {
  throw new Error("GROQ_API_KEY environment variable is missing or empty.");
}

const groq = new Groq({ apiKey });


export const fetchChatResponse = async (userInput: string) => {
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
      stream: false, // Adjust as needed
      stop: null
    });

    return chatCompletion.choices[0]?.message?.content || "No response from AI.";
  } catch (error) {
    console.error("Error fetching chat response:", error);
    throw new Error("Failed to fetch response from AI.");
  }
};