import { SignUp } from "@clerk/nextjs";

export default function Page() {
  return (
    <div className="flex justify-center py-24 bg-black">
      <SignUp />
    </div>
  );
}