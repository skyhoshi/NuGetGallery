﻿CREATE PROCEDURE [jobs].[CompleteInvocation]
	@Id uniqueidentifier,
	@Version int,
	@Status nvarchar(50),
	@Result nvarchar(50),
	@ResultMessage nvarchar(MAX),
	@InstanceName nvarchar(100)
AS
	-- Add a new row for the specified Invocation indicating its new state and completion marker
	INSERT INTO [private].InvocationsStore(
			[Id],
			[Job],
			[Source],
			[Payload],
			[Status],
			[Result],
			[ResultMessage],
			[UpdatedBy],
			[IsContinuation],
			[DequeueCount],
			[Complete],
			[Dequeued],
			[QueuedAt], 
			[NextVisibleAt],
			[UpdatedAt])
	OUTPUT	inserted.*
	SELECT	Id,
			Job, 
			Source, 
			Payload, 
			@Status AS [Status],
			@Result AS [Result],
			@ResultMessage AS [ResultMessage],
			@InstanceName AS [UpdatedBy],
			IsContinuation,
			DequeueCount,
			1 AS [Complete],
			Dequeued,
			QueuedAt,
			[NextVisibleAt],
			SYSDATETIMEOFFSET() AS [UpdatedAt]
	FROM	[jobs].ActiveInvocations
	WHERE	[Id] = @Id AND [Version] = @Version
