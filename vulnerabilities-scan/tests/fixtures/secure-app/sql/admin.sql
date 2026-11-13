-- Admin helper, secure mirror image of the vulnerable one.
USE master;
GO

-- xp_cmdshell is disabled on this instance; administrative work runs through an
-- Agent job whose steps are fixed at deploy time.
SELECT name, value_in_use
FROM sys.configurations
WHERE name = 'xp_cmdshell';
GO
