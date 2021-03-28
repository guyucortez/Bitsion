USE [master]
GO
/****** Object:  Database [WebApiDB]    Script Date: 3/28/2021 11:58:24 AM ******/
CREATE DATABASE [WebApiDB]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'WebApiDB', FILENAME = N'E:\dev\DB\Data\WebApiDB.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'WebApiDB_log', FILENAME = N'E:\dev\DB\Logs\WebApiDB_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
GO
ALTER DATABASE [WebApiDB] SET COMPATIBILITY_LEVEL = 140
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [WebApiDB].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [WebApiDB] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [WebApiDB] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [WebApiDB] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [WebApiDB] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [WebApiDB] SET ARITHABORT OFF 
GO
ALTER DATABASE [WebApiDB] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [WebApiDB] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [WebApiDB] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [WebApiDB] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [WebApiDB] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [WebApiDB] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [WebApiDB] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [WebApiDB] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [WebApiDB] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [WebApiDB] SET  ENABLE_BROKER 
GO
ALTER DATABASE [WebApiDB] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [WebApiDB] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [WebApiDB] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [WebApiDB] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [WebApiDB] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [WebApiDB] SET READ_COMMITTED_SNAPSHOT ON 
GO
ALTER DATABASE [WebApiDB] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [WebApiDB] SET RECOVERY FULL 
GO
ALTER DATABASE [WebApiDB] SET  MULTI_USER 
GO
ALTER DATABASE [WebApiDB] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [WebApiDB] SET DB_CHAINING OFF 
GO
ALTER DATABASE [WebApiDB] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [WebApiDB] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [WebApiDB] SET DELAYED_DURABILITY = DISABLED 
GO
EXEC sys.sp_db_vardecimal_storage_format N'WebApiDB', N'ON'
GO
ALTER DATABASE [WebApiDB] SET QUERY_STORE = OFF
GO
USE [WebApiDB]
GO
/****** Object:  Table [dbo].[__EFMigrationsHistory]    Script Date: 3/28/2021 11:58:25 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[__EFMigrationsHistory](
	[MigrationId] [nvarchar](150) NOT NULL,
	[ProductVersion] [nvarchar](32) NOT NULL,
 CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY CLUSTERED 
(
	[MigrationId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Accounts]    Script Date: 3/28/2021 11:58:25 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Accounts](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Title] [nvarchar](100) NULL,
	[FirstName] [nvarchar](100) NULL,
	[LastName] [nvarchar](100) NULL,
	[UserName] [nvarchar](100) NULL,
	[PasswordHash] [nvarchar](100) NULL,
	[AcceptTerms] [bit] NOT NULL,
	[Role] [int] NOT NULL,
	[VerificationToken] [nvarchar](100) NULL,
	[Verified] [datetime2](7) NULL,
	[ResetToken] [nvarchar](100) NULL,
	[ResetTokenExpires] [datetime2](7) NULL,
	[PasswordReset] [datetime2](7) NULL,
	[Created] [datetime2](7) NOT NULL,
	[Updated] [datetime2](7) NULL,
 CONSTRAINT [PK_Accounts] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RefreshToken]    Script Date: 3/28/2021 11:58:25 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RefreshToken](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[AccountId] [int] NOT NULL,
	[Token] [nvarchar](100) NULL,
	[Expires] [datetime2](7) NOT NULL,
	[Created] [datetime2](7) NOT NULL,
	[CreatedByIp] [nvarchar](100) NULL,
	[Revoked] [datetime2](7) NULL,
	[RevokedByIp] [nvarchar](100) NULL,
	[ReplacedByToken] [nvarchar](100) NULL,
 CONSTRAINT [PK_RefreshToken] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Index [IX_RefreshToken_AccountId]    Script Date: 3/28/2021 11:58:25 AM ******/
CREATE NONCLUSTERED INDEX [IX_RefreshToken_AccountId] ON [dbo].[RefreshToken]
(
	[AccountId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
ALTER TABLE [dbo].[RefreshToken]  WITH CHECK ADD  CONSTRAINT [FK_RefreshToken_Accounts_AccountId] FOREIGN KEY([AccountId])
REFERENCES [dbo].[Accounts] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[RefreshToken] CHECK CONSTRAINT [FK_RefreshToken_Accounts_AccountId]
GO
USE [master]
GO
ALTER DATABASE [WebApiDB] SET  READ_WRITE 
GO
