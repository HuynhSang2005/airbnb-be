import bcrypt from 'bcryptjs';
export const hashPassword = async (password: number | string) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password.toString(), salt);
};
