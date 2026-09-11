"""
AI-Powered Forensic Analysis using NVIDIA Step-3.5-Flash API.
Feeds extracted metadata to the LLM and generates a human-readable
forensic summary + an AI-determined originality score.
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

NVIDIA_API_KEY = "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"
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
MODEL_NAME = "stepfun-ai/step-3.5-flash"

SYSTEM_PROMPT = """You are a digital forensics expert. Analyze the given file metadata and produce a forensic analysis.

You MUST respond with ONLY a valid JSON object (no markdown, no code fences, no explanation outside the JSON).
The JSON must have exactly these two keys:

{
  "forensic_summary": "A 3-5 sentence human-readable forensic analysis of the file. Mention any suspicious findings like timestamp mismatches, editing software traces, missing metadata fields, or other red flags. If everything looks clean, say so.",
  "ai_originality_score": <integer from 0 to 100>
}

Scoring guidelines for ai_originality_score:
- 90-100: File appears completely original. Timestamps match, metadata is complete, no editing software traces.
- 70-89: Minor concerns but likely original. Small timestamp gaps, some metadata present.
- 50-69: Moderate concerns. Editing software detected, timestamp gaps, or incomplete metadata.
- 30-49: Significant modification indicators. Clear editing traces, large timestamp gaps, or modified-before-created anomaly.
- 0-29: Heavily modified or fabricated. Multiple red flags, severe timestamp manipulation, or known tampering tools.

Be specific about what you observe in the metadata. Reference actual values from the data provided."""


def analyze_metadata(metadata_dict: dict) -> dict:
    """
    Call NVIDIA Step-3.5-Flash to generate forensic analysis.
    
    Args:
        metadata_dict: dict with keys like filename, mime_type, created_at_internal,
                       modified_at_internal, extra, hash_value, originality_score, etc.
    
    Returns:
        dict with keys:
            - forensic_summary: str (human-readable analysis)
            - ai_originality_score: float (0-100)
        Or empty dict on failure.
    """
    try:
        from openai import OpenAI
        
        client = OpenAI(
            base_url=NVIDIA_BASE_URL,
            api_key=NVIDIA_API_KEY,
        )

        # Build a clean metadata string for the AI
        meta_summary = _build_meta_prompt(metadata_dict)

        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this file metadata:\n\n{meta_summary}"},
            ],
            temperature=0.3,
            top_p=0.9,
            max_tokens=4096,
            stream=False,
        )

        message = completion.choices[0].message
        
        # In reasoning models, content might be empty if it only outputs reasoning,
        # or if it hits token limit. Safely get content or fallback to reasoning string.
        raw_response = getattr(message, "content", "") or ""
        raw_response = raw_response.strip()

        if not raw_response:
            # Fallback to try and pull from reasoning_content if content is entirely empty
            reasoning = getattr(message, "reasoning_content", "") or ""
            raw_response = reasoning.strip()
            
            # Since sometimes the API puts the whole response in a custom attribute for reasoning
            # models, we also check if there's a custom attribute in the pydantic dump.
            try:
                dumped = message.model_dump()
                if not raw_response and "reasoning" in dumped:
                    raw_response = dumped["reasoning"].strip()
            except Exception:
                pass
        
        # Parse JSON response — handle potential markdown wrapping
        json_str = raw_response
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()

        # Try to find a JSON object in the text if markdown parsing failed to isolate it
        if "{" in json_str and "}" in json_str:
            start_idx = json_str.find("{")
            end_idx = json_str.rfind("}") + 1
            json_str = json_str[start_idx:end_idx]

        result = json.loads(json_str)

        forensic_summary = result.get("forensic_summary", "Analysis could not be generated.")
        ai_score = result.get("ai_originality_score", None)
        
        # Validate score range
        if ai_score is not None:
            ai_score = max(0, min(100, int(ai_score)))

        return {
            "forensic_summary": forensic_summary,
            "ai_originality_score": float(ai_score) if ai_score is not None else None,
        }

    except json.JSONDecodeError as e:
        logger.error(f"AI response JSON parse error: {e}. Raw: {raw_response[:200] if 'raw_response' in locals() else 'None'}")
        # Try to salvage — return raw text as summary
        return {
            "forensic_summary": raw_response[:500] if 'raw_response' in locals() else "AI analysis failed — invalid response format.",
            "ai_originality_score": None,
        }
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {
            "forensic_summary": None,
            "ai_originality_score": None,
        }


def _build_meta_prompt(meta: dict) -> str:
    """Build a structured metadata string for the AI prompt."""
    lines = []
    
    if meta.get("filename"):
        lines.append(f"Filename: {meta['filename']}")
    if meta.get("mime_type"):
        lines.append(f"MIME Type: {meta['mime_type']}")
    if meta.get("file_size"):
        size_bytes = meta["file_size"]
        if size_bytes < 1024:
            size_str = f"{size_bytes} bytes"
        elif size_bytes < 1024*1024:
            size_str = f"{size_bytes/1024:.1f} KB"
        else:
            size_str = f"{size_bytes/1024/1024:.1f} MB"
        lines.append(f"File Size: {size_str}")
    
    if meta.get("created_at_internal"):
        lines.append(f"Internal Created Date: {meta['created_at_internal']}")
    else:
        lines.append("Internal Created Date: Not available")
    
    if meta.get("modified_at_internal"):
        lines.append(f"Internal Modified Date: {meta['modified_at_internal']}")
    else:
        lines.append("Internal Modified Date: Not available")
    
    if meta.get("hash_value"):
        lines.append(f"SHA-512 Hash: {meta['hash_value'][:32]}...")
    
    if meta.get("originality_score") is not None:
        lines.append(f"Static Originality Score: {meta['originality_score']}%")
    
    # Extra metadata
    extra = meta.get("extra", {})
    if extra:
        lines.append("\nAdditional Metadata:")
        for key, val in extra.items():
            display_key = key.replace("_", " ").title()
            lines.append(f"  {display_key}: {val}")
    
    return "\n".join(lines)
