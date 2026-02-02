<#
.SYNOPSIS
    DLP Test File Generator - Creates synthetic sensitive data files for DLP testing
    
.DESCRIPTION
    This script generates test files containing fake/synthetic PII and sensitive data
    for testing Data Loss Prevention (DLP) solutions. All data is artificially generated
    and does not represent real individuals or accounts.
    
.PARAMETER OutputPath
    The directory where test files will be created
    
.PARAMETER FileCount
    Number of files to generate (default: 150)
    
.PARAMETER TrackingFile
    Path to the JSON file that tracks created files (default: dlp-test-tracking.json in OutputPath)

.PARAMETER Clean
    If specified, removes all files tracked in the tracking JSON file

.EXAMPLE
    .\DLP-Test-File-Generator.ps1 -OutputPath "C:\DLP-Test" -FileCount 150
    
.EXAMPLE
    .\DLP-Test-File-Generator.ps1 -OutputPath "C:\DLP-Test" -Clean

.NOTES
    Author: Security Testing Team
    Purpose: DLP/EDR Defense Validation
    All generated data is synthetic and for testing purposes only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [int]$FileCount = 150,
    
    [Parameter(Mandatory = $false)]
    [string]$TrackingFile,
    
    [Parameter(Mandatory = $false)]
    [switch]$Clean
)

#region Helper Functions

function Write-Banner {
    $banner = @"
╔═══════════════════════════════════════════════════════════════╗
║           DLP Test File Generator v1.0                        ║
║           For Security Testing Purposes Only                  ║
╚═══════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Get-RandomName {
    $firstNames = @('James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 'Michael', 'Linda', 
                    'William', 'Elizabeth', 'David', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica',
                    'Thomas', 'Sarah', 'Charles', 'Karen', 'Emma', 'Oliver', 'Sophia', 'Liam', 'Ava')
    $lastNames = @('Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
                   'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson',
                   'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson', 'White')
    
    return "$($firstNames | Get-Random) $($lastNames | Get-Random)"
}

function Get-FakeSSN {
    # Generate fake SSN using invalid area numbers (900-999 range which is not assigned)
    # This ensures the SSN cannot belong to a real person
    $area = Get-Random -Minimum 900 -Maximum 1000
    $group = Get-Random -Minimum 10 -Maximum 100
    $serial = Get-Random -Minimum 1000 -Maximum 10000
    return "$area-$group-$serial"
}

function Get-FakeCreditCard {
    param([string]$Type = "random")
    
    # Generate fake credit card numbers using test/invalid ranges
    # These use industry-standard test prefixes that will never be real cards
    
    $types = @{
        'visa_test' = '4111111111111111'      # Standard Visa test number
        'mc_test' = '5500000000000004'         # Standard MC test number  
        'amex_test' = '340000000000009'        # Standard Amex test number
        'discover_test' = '6011000000000004'   # Standard Discover test number
        # Generate random-looking but invalid numbers
        'visa_fake' = "4$(Get-Random -Minimum 100000000000000 -Maximum 999999999999999)"
        'mc_fake' = "5$(Get-Random -Minimum 100000000000000 -Maximum 599999999999999)"
        'amex_fake' = "3$(Get-Random -Minimum 40000000000000 -Maximum 79999999999999)"
    }
    
    if ($Type -eq "random") {
        return $types.Values | Get-Random
    }
    return $types[$Type]
}

function Get-FakeBankAccount {
    # Generate fake routing and account numbers
    # Using 000000000 prefix for routing (invalid) and random account
    $routing = "0$(Get-Random -Minimum 10000000 -Maximum 99999999)"
    $account = Get-Random -Minimum 100000000000 -Maximum 999999999999
    return @{
        Routing = $routing
        Account = $account.ToString()
    }
}

function Get-FakeAddress {
    $streets = @('Main St', 'Oak Ave', 'Maple Dr', 'Cedar Ln', 'Pine Rd', 'Elm St', 'Washington Blvd',
                 'Park Ave', 'Lake Dr', 'Hill Rd', 'River Rd', 'Forest Ave', 'Sunset Blvd', 'Broadway')
    $cities = @('Springfield', 'Riverside', 'Franklin', 'Clinton', 'Madison', 'Georgetown', 'Salem',
                'Bristol', 'Fairview', 'Manchester', 'Oakland', 'Burlington', 'Ashland', 'Clayton')
    $states = @('CA', 'TX', 'FL', 'NY', 'PA', 'IL', 'OH', 'GA', 'NC', 'MI', 'NJ', 'VA', 'WA', 'AZ')
    
    $number = Get-Random -Minimum 100 -Maximum 9999
    $zip = Get-Random -Minimum 10000 -Maximum 99999
    
    return "$number $($streets | Get-Random), $($cities | Get-Random), $($states | Get-Random) $zip"
}

function Get-FakeEmail {
    param([string]$Name)
    $domains = @('testcorp.invalid', 'example.com', 'test.invalid', 'fakeemail.test', 'notreal.invalid')
    $cleanName = $Name.ToLower().Replace(' ', '.')
    return "$cleanName@$($domains | Get-Random)"
}

function Get-FakePhone {
    # Using 555 exchange (reserved for fictional use)
    $area = Get-Random -Minimum 200 -Maximum 999
    $subscriber = Get-Random -Minimum 1000 -Maximum 9999
    return "($area) 555-$subscriber"
}

function Get-FakeDOB {
    $year = Get-Random -Minimum 1950 -Maximum 2006
    $month = Get-Random -Minimum 1 -Maximum 13
    $day = Get-Random -Minimum 1 -Maximum 29
    return (Get-Date -Year $year -Month $month -Day $day).ToString("MM/dd/yyyy")
}

function Get-FakeMedicalRecord {
    $conditions = @('Hypertension', 'Type 2 Diabetes', 'Asthma', 'Arthritis', 'Anxiety', 
                    'Depression', 'Allergies', 'Back Pain', 'Migraine', 'High Cholesterol')
    $medications = @('Lisinopril', 'Metformin', 'Albuterol', 'Ibuprofen', 'Sertraline',
                     'Omeprazole', 'Atorvastatin', 'Amlodipine', 'Gabapentin', 'Levothyroxine')
    
    return @{
        MRN = "MRN$(Get-Random -Minimum 100000 -Maximum 999999)"
        Condition = $conditions | Get-Random
        Medication = $medications | Get-Random
        Provider = "Dr. $(Get-RandomName)"
    }
}

function Get-FakeSalary {
    return Get-Random -Minimum 35000 -Maximum 250000
}

#endregion

#region Content Generators

function New-EmployeeRecord {
    $name = Get-RandomName
    $ssn = Get-FakeSSN
    $dob = Get-FakeDOB
    $address = Get-FakeAddress
    $email = Get-FakeEmail -Name $name
    $phone = Get-FakePhone
    $salary = Get-FakeSalary
    $bank = Get-FakeBankAccount
    $hireDate = (Get-Date).AddDays(-(Get-Random -Minimum 30 -Maximum 3650)).ToString("MM/dd/yyyy")
    $departments = @('Engineering', 'Sales', 'Marketing', 'Finance', 'HR', 'Operations', 'Legal', 'IT')
    $titles = @('Manager', 'Director', 'Analyst', 'Specialist', 'Coordinator', 'Engineer', 'Associate')
    
    return @"
═══════════════════════════════════════════════════════════════
                    EMPLOYEE RECORD - CONFIDENTIAL
═══════════════════════════════════════════════════════════════

PERSONAL INFORMATION
--------------------
Full Name:          $name
Date of Birth:      $dob
Social Security:    $ssn
Home Address:       $address
Email:              $email
Phone:              $phone

EMPLOYMENT DETAILS
------------------
Employee ID:        EMP$(Get-Random -Minimum 10000 -Maximum 99999)
Department:         $($departments | Get-Random)
Title:              $($titles | Get-Random)
Hire Date:          $hireDate
Annual Salary:      `$$($salary.ToString('N0'))

DIRECT DEPOSIT INFORMATION
--------------------------
Bank Routing:       $($bank.Routing)
Account Number:     $($bank.Account)

═══════════════════════════════════════════════════════════════
THIS DOCUMENT CONTAINS SENSITIVE PII - HANDLE WITH CARE
TEST DATA - NOT A REAL PERSON
═══════════════════════════════════════════════════════════════
"@
}

function New-FinancialReport {
    $ccNumbers = 1..5 | ForEach-Object { Get-FakeCreditCard }
    $customers = 1..5 | ForEach-Object { 
        [PSCustomObject]@{
            Name = Get-RandomName
            Card = Get-FakeCreditCard
            Amount = Get-Random -Minimum 100 -Maximum 10000
        }
    }
    
    $totalAmount = ($customers | Measure-Object -Property Amount -Sum).Sum
    if ($null -eq $totalAmount) { $totalAmount = 0 }
    
    return @"
═══════════════════════════════════════════════════════════════
           FINANCIAL TRANSACTION REPORT - CONFIDENTIAL
                    $(Get-Date -Format "MMMM yyyy")
═══════════════════════════════════════════════════════════════

CUSTOMER PAYMENT RECORDS
------------------------
$($customers | ForEach-Object {
"Customer: $($_.Name)
Card Number: $($_.Card)
Transaction Amount: `$$($_.Amount.ToString('N2'))
Transaction ID: TXN$(Get-Random -Minimum 100000000 -Maximum 999999999)
---"
} | Out-String)

SUMMARY
-------
Total Transactions: $($customers.Count)
Total Amount: `$$($totalAmount.ToString('N2'))

═══════════════════════════════════════════════════════════════
CONTAINS PAYMENT CARD INDUSTRY (PCI) DATA - RESTRICTED ACCESS
TEST DATA - NOT REAL TRANSACTIONS
═══════════════════════════════════════════════════════════════
"@
}

function New-HROnboardingPacket {
    $name = Get-RandomName
    $ssn = Get-FakeSSN
    
    return @"
═══════════════════════════════════════════════════════════════
              NEW HIRE ONBOARDING PACKET
                    HUMAN RESOURCES
═══════════════════════════════════════════════════════════════

FORM W-4 INFORMATION
--------------------
Employee Name:      $name
Social Security #:  $ssn
Filing Status:      Single / Married (circle one)
Allowances:         ___

FORM I-9 VERIFICATION
---------------------
Full Legal Name:    $name
Date of Birth:      $(Get-FakeDOB)
SSN:                $ssn
Citizenship Status: U.S. Citizen

EMERGENCY CONTACT
-----------------
Contact Name:       $(Get-RandomName)
Relationship:       Spouse
Phone:              $(Get-FakePhone)

DIRECT DEPOSIT AUTHORIZATION
----------------------------
Bank Name:          First National Test Bank
Routing Number:     $((Get-FakeBankAccount).Routing)
Account Number:     $((Get-FakeBankAccount).Account)
Account Type:       Checking

Signature: _________________________  Date: ____________

═══════════════════════════════════════════════════════════════
CONFIDENTIAL HR DOCUMENT - AUTHORIZED PERSONNEL ONLY
TEST DATA - NOT A REAL PERSON
═══════════════════════════════════════════════════════════════
"@
}

function New-MedicalRecord {
    $name = Get-RandomName
    $ssn = Get-FakeSSN
    $medical = Get-FakeMedicalRecord
    
    return @"
═══════════════════════════════════════════════════════════════
              PATIENT MEDICAL RECORD - HIPAA PROTECTED
═══════════════════════════════════════════════════════════════

PATIENT DEMOGRAPHICS
--------------------
Patient Name:       $name
Date of Birth:      $(Get-FakeDOB)
SSN:                $ssn
Medical Record #:   $($medical.MRN)
Address:            $(Get-FakeAddress)
Phone:              $(Get-FakePhone)
Emergency Contact:  $(Get-RandomName) - $(Get-FakePhone)

INSURANCE INFORMATION
---------------------
Provider:           Test Health Insurance Co.
Policy Number:      POL$(Get-Random -Minimum 1000000 -Maximum 9999999)
Group Number:       GRP$(Get-Random -Minimum 10000 -Maximum 99999)
Subscriber SSN:     $ssn

CLINICAL INFORMATION
--------------------
Primary Diagnosis:  $($medical.Condition)
Current Medications: $($medical.Medication)
Attending Physician: $($medical.Provider)
Last Visit:         $((Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 90)).ToString("MM/dd/yyyy"))

NOTES
-----
Patient presents with symptoms consistent with $($medical.Condition).
Continuing current treatment plan with $($medical.Medication).
Follow-up scheduled in 30 days.

═══════════════════════════════════════════════════════════════
PROTECTED HEALTH INFORMATION (PHI) - HIPAA REGULATIONS APPLY
TEST DATA - NOT A REAL PATIENT
═══════════════════════════════════════════════════════════════
"@
}

function New-TaxDocument {
    $name = Get-RandomName
    $ssn = Get-FakeSSN
    $wages = Get-Random -Minimum 40000 -Maximum 200000
    $fedWithheld = [math]::Round($wages * 0.22, 2)
    $ssWithheld = [math]::Round($wages * 0.062, 2)
    $medWithheld = [math]::Round($wages * 0.0145, 2)
    
    return @"
═══════════════════════════════════════════════════════════════
                         FORM W-2
              Wage and Tax Statement - $((Get-Date).Year - 1)
═══════════════════════════════════════════════════════════════

EMPLOYER INFORMATION                    EMPLOYEE INFORMATION
----------------------                  ---------------------
EIN: 00-0000000                        SSN: $ssn
Test Corporation Inc.                   $name
123 Business Park Dr                    $(Get-FakeAddress)
Anytown, ST 00000

═══════════════════════════════════════════════════════════════
Box 1 - Wages, tips, other:     `$$($wages.ToString('N2'))
Box 2 - Federal tax withheld:   `$$($fedWithheld.ToString('N2'))
Box 3 - Social Security wages:  `$$($wages.ToString('N2'))
Box 4 - Social Security tax:    `$$($ssWithheld.ToString('N2'))
Box 5 - Medicare wages:         `$$($wages.ToString('N2'))
Box 6 - Medicare tax:           `$$($medWithheld.ToString('N2'))
═══════════════════════════════════════════════════════════════

Control Number: $(Get-Random -Minimum 100000 -Maximum 999999)

═══════════════════════════════════════════════════════════════
OFFICIAL TAX DOCUMENT - CONFIDENTIAL
TEST DATA - NOT A REAL TAX FORM
═══════════════════════════════════════════════════════════════
"@
}

function New-CustomerDatabase {
    $records = 1..10 | ForEach-Object {
        $name = Get-RandomName
        @{
            ID = "CUST$(Get-Random -Minimum 10000 -Maximum 99999)"
            Name = $name
            SSN = Get-FakeSSN
            DOB = Get-FakeDOB
            Email = Get-FakeEmail -Name $name
            Phone = Get-FakePhone
            Address = Get-FakeAddress
            CreditCard = Get-FakeCreditCard
        }
    }
    
    $output = @"
═══════════════════════════════════════════════════════════════
              CUSTOMER DATABASE EXPORT - CONFIDENTIAL
              Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
═══════════════════════════════════════════════════════════════

"@
    
    foreach ($record in $records) {
        $output += @"
CUSTOMER ID: $($record.ID)
-----------------------------------------
Name:           $($record.Name)
SSN:            $($record.SSN)
Date of Birth:  $($record.DOB)
Email:          $($record.Email)
Phone:          $($record.Phone)
Address:        $($record.Address)
Payment Card:   $($record.CreditCard)

"@
    }
    
    $output += @"
═══════════════════════════════════════════════════════════════
TOTAL RECORDS: $($records.Count)
CONTAINS PII AND PCI DATA - RESTRICTED ACCESS ONLY
TEST DATA - NOT REAL CUSTOMERS
═══════════════════════════════════════════════════════════════
"@
    
    return $output
}

function New-BankStatement {
    $name = Get-RandomName
    $bank = Get-FakeBankAccount
    $balance = Get-Random -Minimum 1000 -Maximum 50000
    
    $transactions = 1..15 | ForEach-Object {
        [PSCustomObject]@{
            Date = (Get-Date).AddDays(-$_).ToString("MM/dd")
            Description = @('Direct Deposit', 'ATM Withdrawal', 'Online Transfer', 'Debit Card', 
                          'Check #' + (Get-Random -Minimum 1000 -Maximum 9999), 'ACH Payment',
                          'Wire Transfer', 'Mobile Deposit') | Get-Random
            Amount = if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) { 
                        Get-Random -Minimum 50 -Maximum 500 
                     } else { 
                        -(Get-Random -Minimum 20 -Maximum 300) 
                     }
        }
    }
    
    # Calculate totals safely
    $totalDeposits = ($transactions | Where-Object { $_.Amount -gt 0 } | Measure-Object -Property Amount -Sum).Sum
    if ($null -eq $totalDeposits) { $totalDeposits = 0 }
    $totalWithdrawals = ($transactions | Where-Object { $_.Amount -lt 0 } | Measure-Object -Property Amount -Sum).Sum
    if ($null -eq $totalWithdrawals) { $totalWithdrawals = 0 }
    $endingBalance = $balance + $totalDeposits + $totalWithdrawals
    
    return @"
═══════════════════════════════════════════════════════════════
                    BANK STATEMENT
              First National Test Bank
              Statement Period: $(Get-Date -Format "MMMM yyyy")
═══════════════════════════════════════════════════════════════

ACCOUNT HOLDER INFORMATION
--------------------------
Name:               $name
Address:            $(Get-FakeAddress)
Account Number:     $($bank.Account)
Routing Number:     $($bank.Routing)
Account Type:       Personal Checking

ACCOUNT SUMMARY
---------------
Beginning Balance:  `$$($balance.ToString('N2'))
Total Deposits:     `$$($totalDeposits.ToString('N2'))
Total Withdrawals:  `$$(([Math]::Abs($totalWithdrawals)).ToString('N2'))
Ending Balance:     `$$($endingBalance.ToString('N2'))

TRANSACTION HISTORY
-------------------
DATE        DESCRIPTION                 AMOUNT
----        -----------                 ------
$($transactions | ForEach-Object {
    "$($_.Date)      $($_.Description.PadRight(25)) $(if($_.Amount -ge 0){'+'})$($_.Amount.ToString('N2'))"
} | Out-String)

═══════════════════════════════════════════════════════════════
CONFIDENTIAL FINANCIAL DOCUMENT
TEST DATA - NOT A REAL BANK STATEMENT
═══════════════════════════════════════════════════════════════
"@
}

function New-PasswordList {
    # Generates a fake password list document (something DLP should definitely catch!)
    $systems = @('Domain Admin', 'VPN', 'Email Server', 'Database', 'AWS Console', 
                 'Azure Portal', 'Firewall', 'Backup System', 'HR System', 'Financial App')
    
    $output = @"
═══════════════════════════════════════════════════════════════
              SYSTEM CREDENTIALS - TOP SECRET
              Last Updated: $(Get-Date -Format "yyyy-MM-dd")
═══════════════════════════════════════════════════════════════

WARNING: UNAUTHORIZED ACCESS PROHIBITED

ADMINISTRATOR CREDENTIALS
-------------------------
"@
    
    foreach ($system in $systems) {
        $output += @"
System:     $system
Username:   admin_$(Get-Random -Minimum 100 -Maximum 999)
Password:   $((-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | ForEach-Object {[char]$_})))

"@
    }
    
    $output += @"
═══════════════════════════════════════════════════════════════
DO NOT SHARE - DO NOT EMAIL - DO NOT PRINT
TEST DATA - NOT REAL CREDENTIALS
═══════════════════════════════════════════════════════════════
"@
    
    return $output
}

function New-SSNList {
    $output = @"
═══════════════════════════════════════════════════════════════
              EMPLOYEE SSN VERIFICATION LIST
              $(Get-Date -Format "MMMM yyyy")
═══════════════════════════════════════════════════════════════

For I-9 verification purposes only. Handle with extreme care.

NAME                          SSN              VERIFIED
----                          ---              --------
"@
    
    1..25 | ForEach-Object {
        $name = Get-RandomName
        $output += "$($name.PadRight(30))$(Get-FakeSSN)     Yes`n"
    }
    
    $output += @"

═══════════════════════════════════════════════════════════════
HIGHLY CONFIDENTIAL - PII DATA
TEST DATA - NOT REAL SSNS
═══════════════════════════════════════════════════════════════
"@
    
    return $output
}

function New-CreditCardBatch {
    $output = @"
═══════════════════════════════════════════════════════════════
              PAYMENT CARD BATCH FILE
              Batch ID: BATCH$(Get-Random -Minimum 100000 -Maximum 999999)
              Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
═══════════════════════════════════════════════════════════════

PCI-DSS RESTRICTED - AUTHORIZED PERSONNEL ONLY

CARD_NUMBER,EXPIRY,CVV,CARDHOLDER,AMOUNT
"@
    
    1..30 | ForEach-Object {
        $name = Get-RandomName
        $month = (Get-Random -Minimum 1 -Maximum 13).ToString("00")
        $year = (Get-Random -Minimum 25 -Maximum 30).ToString("00")
        $cvv = Get-Random -Minimum 100 -Maximum 1000
        $amount = Get-Random -Minimum 10 -Maximum 5001
        $output += "$(Get-FakeCreditCard),$month/$year,$cvv,$name,`$$($amount.ToString('N2'))`n"
    }
    
    $output += @"

═══════════════════════════════════════════════════════════════
END OF BATCH - $((Get-Date).Ticks) RECORDS
TEST DATA - NOT REAL CARD NUMBERS
═══════════════════════════════════════════════════════════════
"@
    
    return $output
}

#endregion

#region File Creation

function New-TestFile {
    param(
        [string]$OutputPath,
        [string]$FileType,
        [string]$ContentType
    )
    
    # Generate content based on type
    $content = switch ($ContentType) {
        'Employee'      { New-EmployeeRecord }
        'Financial'     { New-FinancialReport }
        'HROnboarding'  { New-HROnboardingPacket }
        'Medical'       { New-MedicalRecord }
        'Tax'           { New-TaxDocument }
        'CustomerDB'    { New-CustomerDatabase }
        'BankStatement' { New-BankStatement }
        'Passwords'     { New-PasswordList }
        'SSNList'       { New-SSNList }
        'CreditCards'   { New-CreditCardBatch }
    }
    
    # Generate filename
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $random = Get-Random -Minimum 1000 -Maximum 9999
    $baseName = "${ContentType}_${timestamp}_${random}"
    
    # Create file based on type
    $filePath = switch ($FileType) {
        'txt'  { 
            $path = Join-Path $OutputPath "$baseName.txt"
            $content | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'csv'  {
            $path = Join-Path $OutputPath "$baseName.csv"
            $content | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'log'  {
            $path = Join-Path $OutputPath "$baseName.log"
            $content | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'xml'  {
            $path = Join-Path $OutputPath "$baseName.xml"
            @"
<?xml version="1.0" encoding="UTF-8"?>
<TestDocument type="$ContentType" generated="$(Get-Date -Format "o")">
<Content><![CDATA[
$content
]]></Content>
</TestDocument>
"@ | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'json' {
            $path = Join-Path $OutputPath "$baseName.json"
            @{
                documentType = $ContentType
                generated = (Get-Date -Format "o")
                content = $content
                metadata = @{
                    purpose = "DLP Testing"
                    classification = "Test Data"
                }
            } | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'html' {
            $path = Join-Path $OutputPath "$baseName.html"
            # HTML encode without relying on System.Web
            $encodedContent = $content -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
            @"
<!DOCTYPE html>
<html>
<head>
    <title>$ContentType - Test Document</title>
    <style>
        body { font-family: Consolas, monospace; padding: 20px; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; }
        .warning { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>$ContentType Document</h1>
    <p class="warning">⚠️ TEST DATA - FOR DLP TESTING ONLY</p>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <pre>$encodedContent</pre>
</body>
</html>
"@ | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'rtf' {
            $path = Join-Path $OutputPath "$baseName.rtf"
            # Simple RTF format
            $rtfContent = $content -replace '\\', '\\\\' -replace '\{', '\{' -replace '\}', '\}' -replace "`n", '\par '
            @"
{\rtf1\ansi\deff0
{\fonttbl{\f0 Consolas;}}
\f0\fs20
$rtfContent
}
"@ | Out-File -FilePath $path -Encoding ASCII
            $path
        }
        'md' {
            $path = Join-Path $OutputPath "$baseName.md"
            @"
# $ContentType - Test Document

> ⚠️ **WARNING**: This document contains synthetic test data for DLP validation.

**Generated**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

---

``````
$content
``````

---
*This is test data and does not represent real individuals or accounts.*
"@ | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        # For binary formats, we'll create text files with appropriate extensions
        # that contain structured data DLP should recognize
        'pdf' {
            $path = Join-Path $OutputPath "$baseName.pdf.txt"
            "PDF SIMULATION - Content for DLP Testing`n`n$content" | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'docx' {
            $path = Join-Path $OutputPath "$baseName.docx.txt"
            "DOCX SIMULATION - Content for DLP Testing`n`n$content" | Out-File -FilePath $path -Encoding UTF8
            $path
        }
        'xlsx' {
            $path = Join-Path $OutputPath "$baseName.xlsx.txt"
            "XLSX SIMULATION - Content for DLP Testing`n`n$content" | Out-File -FilePath $path -Encoding UTF8
            $path
        }
    }
    
    return $filePath
}

#endregion

#region Main Execution

function Invoke-FileGeneration {
    param(
        [string]$OutputPath,
        [int]$FileCount,
        [string]$TrackingFile
    )
    
    Write-Banner
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "[+] Created output directory: $OutputPath" -ForegroundColor Green
    }
    
    # Set default tracking file location
    if (-not $TrackingFile) {
        $TrackingFile = Join-Path $OutputPath "dlp-test-tracking.json"
    }
    
    Write-Host "[*] Starting file generation..." -ForegroundColor Yellow
    Write-Host "[*] Output path: $OutputPath" -ForegroundColor Yellow
    Write-Host "[*] Files to create: $FileCount" -ForegroundColor Yellow
    Write-Host ""
    
    # Define content types and file extensions
    $contentTypes = @('Employee', 'Financial', 'HROnboarding', 'Medical', 'Tax', 
                      'CustomerDB', 'BankStatement', 'Passwords', 'SSNList', 'CreditCards')
    $fileTypes = @('txt', 'csv', 'log', 'xml', 'json', 'html', 'rtf', 'md', 
                   'pdf', 'docx', 'xlsx')
    
    # Track created files
    $createdFiles = @()
    $startTime = Get-Date
    
    for ($i = 1; $i -le $FileCount; $i++) {
        $contentType = $contentTypes | Get-Random
        $fileType = $fileTypes | Get-Random
        
        try {
            $filePath = New-TestFile -OutputPath $OutputPath -FileType $fileType -ContentType $contentType
            
            # Ensure file exists and get size safely
            $fileSize = 0
            if (Test-Path $filePath) {
                $fileItem = Get-Item -LiteralPath $filePath -ErrorAction SilentlyContinue
                if ($fileItem) {
                    $fileSize = $fileItem.Length
                }
            }
            
            $fileInfo = [PSCustomObject]@{
                Path = $filePath
                ContentType = $contentType
                FileType = $fileType
                Created = (Get-Date -Format "o")
                Size = $fileSize
            }
            
            $createdFiles += $fileInfo
            
            # Progress indicator
            $percent = [math]::Round(($i / $FileCount) * 100)
            Write-Progress -Activity "Generating DLP Test Files" -Status "$i of $FileCount ($percent%)" -PercentComplete $percent
            
            if ($i % 10 -eq 0) {
                Write-Host "[+] Created $i files..." -ForegroundColor Cyan
            }
        }
        catch {
            Write-Host "[-] Error creating file: $_" -ForegroundColor Red
        }
    }
    
    Write-Progress -Activity "Generating DLP Test Files" -Completed
    
    # Save tracking information
    $totalSize = ($createdFiles | Measure-Object -Property Size -Sum).Sum
    if ($null -eq $totalSize) { $totalSize = 0 }
    
    $trackingData = @{
        GeneratedAt = (Get-Date -Format "o")
        OutputPath = $OutputPath
        TotalFiles = $createdFiles.Count
        TotalSize = $totalSize
        Files = $createdFiles
    }
    
    $trackingData | ConvertTo-Json -Depth 10 | Out-File -FilePath $TrackingFile -Encoding UTF8
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    # Summary
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                    GENERATION COMPLETE" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Files Created:    $($createdFiles.Count)" -ForegroundColor Green
    Write-Host "  Total Size:       $([math]::Round($trackingData.TotalSize / 1KB, 2)) KB" -ForegroundColor Green
    Write-Host "  Duration:         $($duration.TotalSeconds.ToString('N2')) seconds" -ForegroundColor Green
    Write-Host "  Output Path:      $OutputPath" -ForegroundColor Green
    Write-Host "  Tracking File:    $TrackingFile" -ForegroundColor Green
    Write-Host ""
    
    # Breakdown by content type
    Write-Host "  Content Type Breakdown:" -ForegroundColor Yellow
    $createdFiles | Group-Object -Property ContentType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "    $($_.Name.PadRight(15)) : $($_.Count) files" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  File Type Breakdown:" -ForegroundColor Yellow
    $createdFiles | Group-Object -Property FileType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "    $($_.Name.PadRight(8)) : $($_.Count) files" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    return $trackingData
}

function Invoke-Cleanup {
    param(
        [string]$OutputPath,
        [string]$TrackingFile
    )
    
    Write-Banner
    
    # Set default tracking file location
    if (-not $TrackingFile) {
        $TrackingFile = Join-Path $OutputPath "dlp-test-tracking.json"
    }
    
    if (-not (Test-Path $TrackingFile)) {
        Write-Host "[-] Tracking file not found: $TrackingFile" -ForegroundColor Red
        Write-Host "[-] Cannot perform cleanup without tracking information." -ForegroundColor Red
        return
    }
    
    Write-Host "[*] Loading tracking data from: $TrackingFile" -ForegroundColor Yellow
    
    $trackingData = Get-Content $TrackingFile | ConvertFrom-Json
    
    Write-Host "[*] Found $($trackingData.Files.Count) files to clean up" -ForegroundColor Yellow
    Write-Host ""
    
    $removed = 0
    $notFound = 0
    $errors = 0
    
    foreach ($file in $trackingData.Files) {
        try {
            if (Test-Path $file.Path) {
                Remove-Item -Path $file.Path -Force
                $removed++
            }
            else {
                $notFound++
            }
        }
        catch {
            $errors++
            Write-Host "[-] Error removing: $($file.Path) - $_" -ForegroundColor Red
        }
    }
    
    # Remove tracking file
    Remove-Item -Path $TrackingFile -Force -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                    CLEANUP COMPLETE" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Files Removed:    $removed" -ForegroundColor Green
    Write-Host "  Not Found:        $notFound" -ForegroundColor Yellow
    Write-Host "  Errors:           $errors" -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Gray' })
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# Main entry point
if ($Clean) {
    Invoke-Cleanup -OutputPath $OutputPath -TrackingFile $TrackingFile
}
else {
    Invoke-FileGeneration -OutputPath $OutputPath -FileCount $FileCount -TrackingFile $TrackingFile
}

#endregion
