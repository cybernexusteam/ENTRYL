'use client';

import { useUser } from '@clerk/nextjs';

const User = () => {
  const { user, isSignedIn } = useUser();

  if (!isSignedIn) return <div>Not signed in</div>;

  return <div>Hello {user?.firstName}</div>;
};

export default User;