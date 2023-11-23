import { Pipe, PipeTransform } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { ValidationErrors } from '@angular/forms';

@Pipe({
  name: 'safe'
})
export class SafePipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(value: string | ValidationErrors): SafeHtml {
    if (typeof value === 'string') {
      return this.sanitizer.bypassSecurityTrustHtml(value);
    } else if (value instanceof Object) {
      const errorMessage = this.processValidationErrors(value);
      return this.sanitizer.bypassSecurityTrustHtml(errorMessage);
    } else {
      return '';
    }
  }

  private processValidationErrors(errors: ValidationErrors): string {
    let errorMessage = '';
    for (const key in errors) {
      if (errors.hasOwnProperty(key)) {
        const errorValue = errors[key];
        if (typeof errorValue === 'string') {
          errorMessage += `${key}: ${errorValue}<br>`;
        } else if (errorValue instanceof Object) {
          // Handle nested objects, e.g., for pattern validation
          errorMessage += `${key}: ${this.processValidationErrors(errorValue)}<br>`;
        } else {
          errorMessage += `${key}: ${errorValue}<br>`;
        }
      }
    }
    return errorMessage;
  }
}

