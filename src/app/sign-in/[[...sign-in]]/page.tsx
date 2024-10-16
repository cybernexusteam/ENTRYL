import { SignIn } from "@clerk/nextjs";
import { dark, neobrutalism } from "@clerk/themes";
export default function Page() {
  return (
    <div className="flex justify-center py-24 bg-black">
      <SignIn 
      appearance={{
        baseTheme: [dark, neobrutalism],
        variables:{
          colorBackground: "black",
        },
      }}/>
    </div>
  );
}