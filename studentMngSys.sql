USE master;
GO
IF EXISTS (SELECT * FROM sys.databases WHERE name = 'StudentProjectDB')
    DROP DATABASE StudentProjectDB;
GO
CREATE DATABASE StudentProjectDB;
GO
USE StudentProjectDB;
GO

-- --- SCHEMAS ---
GO
CREATE SCHEMA App; 
GO
CREATE SCHEMA Sec; 
GO

-- --- TABLES ---

CREATE TABLE App.Roles (
    RoleID INT PRIMARY KEY IDENTITY(1,1),
    RoleName NVARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE App.Users (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(256) NOT NULL,
    Salt NVARCHAR(50) NOT NULL,
    
    Email NVARCHAR(100) MASKED WITH (FUNCTION = 'email()') NULL,
    
    EncryptedPhone VARBINARY(MAX) NULL, 
    
    RoleID INT FOREIGN KEY REFERENCES App.Roles(RoleID),
    PDPA_Consent BIT DEFAULT 0, 
    CreatedAt DATETIME DEFAULT GETDATE()
);

CREATE TABLE App.Assignments (
    AssignmentID INT PRIMARY KEY IDENTITY(1,1),
    ProjectTitle NVARCHAR(100),
    Description NVARCHAR(255),
    GitHubLink NVARCHAR(200),
    SubmittedBy INT FOREIGN KEY REFERENCES App.Users(UserID),
    SubmissionDate DATETIME DEFAULT GETDATE()
);

CREATE TABLE App.Milestones (
    MilestoneID INT PRIMARY KEY IDENTITY(1,1),
    AssignmentID INT FOREIGN KEY REFERENCES App.Assignments(AssignmentID) ON DELETE CASCADE,
    TaskName NVARCHAR(100),
    IsCompleted BIT DEFAULT 0
);

CREATE TABLE App.Notifications (
    NotifID INT PRIMARY KEY IDENTITY(1,1),
    UserID INT FOREIGN KEY REFERENCES App.Users(UserID),
    Message NVARCHAR(255),
    IsRead BIT DEFAULT 0,
    DateCreated DATETIME DEFAULT GETDATE()
);

CREATE TABLE App.Feedback (
    FeedbackID INT PRIMARY KEY IDENTITY(1,1),
    SubmittedBy INT FOREIGN KEY REFERENCES App.Users(UserID),
    IssueType NVARCHAR(50),
    Message NVARCHAR(MAX),
    DateCreated DATETIME DEFAULT GETDATE()
);

CREATE TABLE Sec.AuditLog (
    AuditID INT PRIMARY KEY IDENTITY(1,1),
    ActionType NVARCHAR(50), 
    TableName NVARCHAR(50),
    RecordID INT,
    UserID INT,
    UserIP NVARCHAR(50),
    Timestamp DATETIME DEFAULT GETDATE(),
    Details NVARCHAR(255)
);

CREATE TABLE Sec.SystemConfig (
    ConfigKey NVARCHAR(50) PRIMARY KEY,
    ConfigValue NVARCHAR(50) 
);

INSERT INTO App.Roles (RoleName) VALUES 
('Admin'),            
('Lecturer'),         
('Student'),          
('External Examiner');

INSERT INTO Sec.SystemConfig VALUES ('AllowUploads', 'TRUE');

-- --- TRIGGERS ---
GO
CREATE TRIGGER trg_AuditAssignments
ON App.Assignments
AFTER INSERT, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT * FROM inserted)
    BEGIN
        INSERT INTO Sec.AuditLog (ActionType, TableName, RecordID, Details)
        SELECT 'INSERT_PROJECT', 'Assignments', AssignmentID, ProjectTitle FROM inserted;
        
        INSERT INTO App.Notifications (UserID, Message)
        SELECT UserID, 'New project submitted!' FROM App.Users WHERE RoleID = 2;
    END

    IF EXISTS (SELECT * FROM deleted)
        INSERT INTO Sec.AuditLog (ActionType, TableName, RecordID, Details)
        SELECT 'DELETE_PROJECT', 'Assignments', AssignmentID, ProjectTitle FROM deleted;
END
GO

-- --- STORED PROCEDURES ---
GO
CREATE PROCEDURE Sec.sp_RegisterUser
    @Username NVARCHAR(50), 
    @PassHash NVARCHAR(256), 
    @Salt NVARCHAR(50), 
    @Email NVARCHAR(100),
    @Phone NVARCHAR(20),
    @RoleID INT
AS
BEGIN
    INSERT INTO App.Users (Username, PasswordHash, Salt, Email, EncryptedPhone, RoleID, PDPA_Consent)
    VALUES (@Username, @PassHash, @Salt, @Email, 
            EncryptByPassPhrase('MySecureKey123', @Phone), 
            @RoleID, 1);
END
GO

CREATE PROCEDURE Sec.sp_GetDecryptedUser
    @Username NVARCHAR(50)
AS
BEGIN
    SELECT UserID, PasswordHash, Salt, RoleID, Email, Username,
    CONVERT(NVARCHAR(50), DecryptByPassPhrase('MySecureKey123', EncryptedPhone)) as Phone
    FROM App.Users WHERE Username = @Username;
END
GO