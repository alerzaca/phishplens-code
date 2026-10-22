#!/usr/bin/env python3

import sys
import subprocess
from pathlib import Path
import shutil


class EmailProcessingPipeline:
    def __init__(self, input_dir: Path, output_base_dir: Path,
                 include_gmail: bool = False):
        self.input_dir = Path(input_dir)
        self.output_base_dir = Path(output_base_dir)
        self.scripts_dir = Path(__file__).resolve().parent
        self.include_gmail = include_gmail
        
        # Final output is the output directory itself.
        self.final_dir = self.output_base_dir

        # Intermediate directories kept under output for easy cleanup.
        self.preprocessed_dir = self.output_base_dir / ".tmp-preprocessed"
        self.anonymized_dir = self.output_base_dir / ".tmp-anonymized"
    
    def run_script(self, script_name: str, args: list, stage_name: str):
        script_path = self.scripts_dir / script_name

        print(f"[{stage_name}]")
        cmd = [sys.executable, str(script_path)] + [str(arg) for arg in args]
        print(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=False, text=True)
        
        if result.returncode != 0:
            print(f"ERROR: {stage_name} failed with exit code {result.returncode}")
            sys.exit(1)

        print(f"OK: {stage_name}")
    
    def cleanup_temp_dirs(self):
        temp_dirs = [
            self.preprocessed_dir,
            self.anonymized_dir,
        ]
        for temp_dir in temp_dirs:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
    
    def run_pipeline(self):
        if not self.input_dir.exists():
            print(f"ERROR: Input directory does not exist: {self.input_dir}")
            sys.exit(1)

        print("EMAIL PROCESSING PIPELINE")
        print(f"Input:  {self.input_dir}")
        print(f"Output: {self.output_base_dir}")
        print(f"Scripts: {self.scripts_dir}")
        
        # Stage 1: Preprocessing
        preprocess_args = [self.input_dir, self.preprocessed_dir]
        self.run_script(
            "email_processor.py",
            preprocess_args,
            "1. PREPROCESSING (headers, IPs, attachments, decoding)"
        )
        
        # Stage 2: Anonymize recipients
        anonymize_args = [self.preprocessed_dir, self.anonymized_dir]
        if self.include_gmail:
            anonymize_args.insert(0, '--include-gmail')
        self.run_script(
            "email_recipient_anonymizer.py",
            anonymize_args,
            "2. ANONYMIZE RECIPIENTS"
        )
        
        # Use anonymized directory as the only final dataset.
        self.final_dir.mkdir(parents=True, exist_ok=True)
        for old_file in self.final_dir.glob('*.eml'):
            old_file.unlink()
        for eml_file in self.anonymized_dir.glob('*.eml'):
            shutil.copy2(eml_file, self.final_dir / eml_file.name)

        # Cleanup
        self.cleanup_temp_dirs()
        
        # Final summary
        count = len(list(self.final_dir.glob('*.eml'))) if self.final_dir.exists() else 0
        print("PIPELINE COMPLETE")
        print(f"Final dataset: {self.final_dir}")
        print(f"Files: {count}")


def main():
    args = sys.argv[1:]
    include_gmail = False

    if '--include-gmail' in args:
        include_gmail = True
        args.remove('--include-gmail')

    if len(args) != 2:
        print("Usage: python email_processing_pipeline.py [--include-gmail] <input_dir> <output_base_dir>")
        print("\nExample:")
        print("  python email_processing_pipeline.py \\")
        print("    /path/to/oryg/clean-1 \\")
        print("    /path/to/output")
        print("\nOutput structure:")
        print("  output/")
        print("    *.eml                     (anonymized dataset)")
        sys.exit(1)
    
    input_dir = Path(args[0])
    output_base_dir = Path(args[1])

    pipeline = EmailProcessingPipeline(
        input_dir,
        output_base_dir,
        include_gmail=include_gmail,
    )
    pipeline.run_pipeline()


if __name__ == '__main__':
    main()
