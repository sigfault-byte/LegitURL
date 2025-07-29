
# LegitURL Analysis Examples

This folder contains real-world examples tested using **LegitURL** and optionally analyzed by an LLM.

- Each example shows:
  - The input URL or email link
  - The exported PDF
  - The structured JSON ( for machine use )
  - the model's reasoning output

These examples are sanitized for personal info but may include real phishing patterns for educational use.

| Case | Input URL | PDF | JSON | ModelOutput|
|------|-----------|-----|-------|-----|
| Amazon Phishing | amazon-link[^1]| [PDF](./PDF/legitURL_Report_2025-06-03T17:43:54Z-amazon-verifcompte.pdf) | [FULLReportJSON](./JSON/FullReport_comsssvnsmrsftp.amazon-verifcompte.com.JSON) | [Gemini](./ModelOutput/GEMINI_FullReport_comsssvnsmrsftp.amazon-verifcompte.com.text)
|EDF ( French National Energy Company) | edf-link[^2] |[PDF](./PDF/legitURL_Report_2025-06-09T13:32:39Z-edf-espaceclient.pdf) | [FULLReportJSON](./JSON/FullReport_edf-espaceclient.json) | [DeepSeek](./ModelOutput/DEEPSEEK_FullReport_edf-espaceclient.txt) 
| ANTAI ( French National agency for automated Offence Processing) | antai-link[^3] | [PDF]('/PDF/legitURL_Report_2025-06-21T05:21:36Z-sonjajuengling.pdf') | [FullReportJSON](./JSON/FullReport_antaiScam_v1.2.json) | [GPT4o](./ModelOutput/GTP4o_FullReport_ANTAI.txt)
| ANTAI_2 | antai2-link[^4]| [PDF](./PDF/legitURL_Report_2025-07-29T09:50:41Z-routieres-justice.pdf) | [FULLReportJSON](./JSON/FullReport_Antai2Scam_v1.6.json) | [Grok3](./ModelOutput/Grok3_fullReport_Antai2.text) |




[^1] : amazon-link : https://comsssvnsmrsftp.amazon-verifcompte.com  
[^2] : edf-link : https://www.surveymonkey.com/tr/v1/te/csIEz8tKbXhhynZd6M6vpxM9ZY6Pwfv9P2SgCz0we5bJLEVtlZvTfNyZpTSRumTiFqhlrvRo1ju_2BEJNmz8qkn6vwVqEy1PFqwDkH3PRNOh90pBpyJEM_2FZbELlEFzj9LBQe_2F_2B9N6BcooIHpC_2Fc7UW5VtpoqfjVHBOEpLna_2F0Thk7F_2FM_2FCwS7SyU6y71Ow8aZd7QO07KgNhIkzDt_2B_2FwtYefRCzXQBZxxmt4Oeoi_2BOUhvI_3D  
[^3] : antai-link : https://mehdiekang.hosted.phplist.com/lists/?p=subscribe&id=1  
[^4] : antai2-link : https://es.surveymonkey.com/tr/v1/te/zETqGd5fvn44ZigHRJ5K9frpZMPLCnIQ3l0TcjTmeWjNZawuj4GHaRm27JaVgQDILDh9YfyLFRCECnwC3OEjwqv_2FyEDB0Y5pxs_2FcKBSBRJ_2F9rC45INGzOQUOL8inNakTKAw5nANl3nDpsxHMwnRdeKSpRH1Qn_2F9S0FvEMMFACjHDZl3eqeI3XqCZSxCvlMUPPhkqGTbZbc_2BQuNS_2BWbH_2F2A_3D_3D

