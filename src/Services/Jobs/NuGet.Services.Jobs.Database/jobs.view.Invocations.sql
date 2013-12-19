﻿CREATE VIEW [jobs].[Invocations] AS 
	WITH cte AS (
		SELECT *, ROW_NUMBER() OVER (PARTITION BY Id ORDER BY [Version] DESC) AS RowNumber
		FROM [private].InvocationsStore
	)
	SELECT * FROM cte WHERE RowNumber = 1
