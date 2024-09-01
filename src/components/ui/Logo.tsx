import Link from "next/link";
import Image from "next/image";
import { motion } from "framer-motion";
import LetterLogo from "./LetterLogo.png";

export const Logo = () => {
    return (
      <Link
        href="#"
        className="font-normal flex space-x-2 items-center text-sm text-black py-1 relative z-20"
      >
        <Image src={LetterLogo} alt='logo'/>
        <motion.span
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="font-medium text-text0 dark:text-white whitespace-pre"
        >
          ENTRYL
        </motion.span>
      </Link>
    );
  };