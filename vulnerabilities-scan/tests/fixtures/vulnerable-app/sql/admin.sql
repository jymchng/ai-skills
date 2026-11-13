-- Admin helper that ships next to the deployment scripts.
USE master;
GO

-- The operating-system shell is reachable from SQL.
EXEC master..xp_cmdshell 'whoami';
GO
