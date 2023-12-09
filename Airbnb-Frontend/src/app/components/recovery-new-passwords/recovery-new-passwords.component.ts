import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormControl, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router, UrlSegment } from '@angular/router';
import { RecoverPasswordDTO } from 'src/app/dto/recoverPasswordDTO';
import { AuthService } from 'src/app/services/auth.service';
import { PasswordStrengthValidator } from 'src/app/services/customValidators';
import { RecoveryPasswordService } from 'src/app/services/recoveryPassword.service';

@Component({
  selector: 'app-recovery-new-passwords',
  templateUrl: './recovery-new-passwords.component.html',
  styleUrls: ['./recovery-new-passwords.component.css']
})
export class RecoveryNewPasswordsComponent implements OnInit {

  formGroup: FormGroup = new FormGroup({
    newPassword: new FormControl(''),
    repeatPassword: new FormControl(''),
  });
  submitted = false;

  constructor(
    private authService: AuthService,
    private formBuilder: FormBuilder,
    private router: Router,
    private recoveryService: RecoveryPasswordService,
    private _snackBar: MatSnackBar
  ) { }



  ngOnInit(): void {
    this.formGroup = this.formBuilder.group({
      newPassword: ['', [Validators.required, Validators.minLength(11), Validators.maxLength(30), PasswordStrengthValidator(), ]],
      repeatPassword: ['', [Validators.required, Validators.minLength(11), Validators.maxLength(30), PasswordStrengthValidator(), ]],
    })
  }

  get f(): { [key: string]: AbstractControl } {
    return this.formGroup.controls;
  }

  onSubmit(){
    this.submitted = true;

    if (this.formGroup.invalid) {
      return;
    }

    let recoverPasswordReq = new RecoverPasswordDTO();
    let userID = '';
    this.recoveryService.currentToken.subscribe(token => userID = token )
    recoverPasswordReq.id = userID;
    recoverPasswordReq.new_password = this.formGroup.get("newPassword")?.value;
    recoverPasswordReq.repeated_new = this.formGroup.get("repeatPassword")?.value;
    if (recoverPasswordReq.new_password != recoverPasswordReq.repeated_new) {
      this._snackBar.open('Passwords don\'t match.', '', {
        duration: 3500,
        panelClass: ['error-snackbar']
      });
      return;
    }

    this.authService.RecoverPassword(recoverPasswordReq)
      .subscribe({
        next: () => {
          this.openSnackBar("Successfully recovered password.", "")
          this.router.navigate(['']);
        },
        error: (err: HttpErrorResponse) => {
          if (err.status === 400) {
            this.openSnackBar("Password is in the blacklist!", "")
          }
          else if (err.status == 406){
            this.openSnackBar("New password not match!", "")
          }
          else if (err.status === 500) {
            this.openSnackBar("Internal server error!", "")
          }
          else if (err.status == 200){
            this.openSnackBar("Password recovered successfully!", "")
          }
        }
      });
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }

}


