-- AlterTable
ALTER TABLE "User" ADD COLUMN     "provider" TEXT,
ADD COLUMN     "providerId" TEXT,
ADD COLUMN     "resetPasswordExpires" TIMESTAMP(3),
ADD COLUMN     "resetPasswordToken" TEXT;
