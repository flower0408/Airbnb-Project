import { AbstractControl, FormControl, ValidationErrors, ValidatorFn } from "@angular/forms";

export function PasswordStrengthValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const value = control.value;

    if (!value) {
      return null;
    }

    const hasUpperCase = /[A-Z]+/.test(value);
    const hasLowerCase = /[a-z]+/.test(value);
    const hasNumeric = /[0-9]+/.test(value);
    const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value);

    const passwordValid = value.length >= 11 && value.length <= 30 && hasUpperCase && hasLowerCase && hasNumeric && hasSpecialChar;

    return !passwordValid ? { passwordStrength: true } : null;
  };
}
export function MaxGuestValidator(/*minGuestControl: AbstractControl*/): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const value = control.value;
    //const minGuestValue = minGuestControl.value;
    const minGuestValue = control.root.get('Minguest')?.value;

    if (!value) {
      return null;
    }

    if (isNaN(value) || isNaN(minGuestValue)) {
      return { invalidNumber: true };
    }

    const maxGuest = parseInt(value, 10);
    const minGuest = parseInt(minGuestValue, 10);

    return maxGuest >= minGuest ? null : { min: true };
  };
}

export function UpperLetterValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const value = control.value;

    if (!value) {
      return null;
    }

    const startsWithUpperCase = /^[A-Z]/.test(value);
    const valid = startsWithUpperCase;

    return !valid ? { upperLetter: true } : null;
  };
}

export function endDayValidator(startDayControlName: string): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const value = control.value;
    const startDay = control.root.get(startDayControlName)?.value;

    if (!value) {
      return null;
    }

    if (isNaN(value) || isNaN(startDay)) {
      return { invalidNumber: true };
    }

    const endDayValue = new Date(value.toDateString());
    const startDayValue = new Date(startDay.toDateString());

    if (
      endDayValue.getFullYear() < startDayValue.getFullYear() ||
      (endDayValue.getFullYear() === startDayValue.getFullYear() &&
        endDayValue.getMonth() < startDayValue.getMonth()) ||
      (endDayValue.getFullYear() === startDayValue.getFullYear() &&
        endDayValue.getMonth() === startDayValue.getMonth() &&
        endDayValue.getDate() <= startDayValue.getDate())
    ) {
      return { validator: true };
    }

    return null;
  };
}



