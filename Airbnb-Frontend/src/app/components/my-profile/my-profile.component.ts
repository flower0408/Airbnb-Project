import {ChangeDetectorRef, Component, OnInit} from '@angular/core';
import { Router } from '@angular/router';
import {User} from "../../models/user.model";
import {UserService} from "../../services/user.service";
import {FormBuilder, FormGroup, Validators} from "@angular/forms";
import {AuthService} from "../../services/auth.service";
import {MatSnackBar, MatSnackBarRef, SimpleSnackBar} from "@angular/material/snack-bar";
import {Observable, tap} from "rxjs";

@Component({
  selector: 'app-my-profile',
  templateUrl: './my-profile.component.html',
  styleUrls: ['./my-profile.component.css']
})
export class MyProfileComponent implements OnInit {

  constructor(private router: Router,
              private userService: UserService,
              private authService: AuthService,
              private fb: FormBuilder,
              private _snackBar: MatSnackBar,
              private cdRef: ChangeDetectorRef,
              ){
    this.usernameForm = this.fb.group({
      newUsername: [this.user.username, [Validators.required, Validators.minLength(4), Validators.maxLength(30), Validators.pattern('[-_a-zA-Z0-9]*')]],
    });
    this.profileForm = this.fb.group({
      firstName: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(20), Validators.pattern('[-_a-zA-Z]*')]],
      lastName: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(20), Validators.pattern('[-_a-zA-Z]*')]],
      gender: ['', [Validators.required]],
      age: ['', [Validators.required, Validators.min(1), Validators.max(100)]],
      residence: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(35), Validators.pattern("^[a-zA-Z0-9\\s,'-]*")]],
      email: ['', [Validators.required, Validators.email, Validators.minLength(3), Validators.maxLength(35)]],
    });
  }

  user: User = new User();
  usernameForm: FormGroup;
  profileForm: FormGroup;

  ngOnInit(): void {

    this.userService.Profile()
      .subscribe({
        next: (data: User) => {
          this.user = data;
          this.profileForm.patchValue({
            firstName: this.user.firstName,
            lastName: this.user.lastName,
            gender: this.user.gender,
            age: this.user.age,
            residence: this.user.residence,
            email: this.user.email,
          });
        },
        error: (error) => {
          console.log(error);
        },
      });

    this.userService.getUser()
      .subscribe({
        next: (data: User) => {
          this.user = data;
          this.usernameForm.patchValue({
            newUsername: this.user.username,
          });
        },
        error: (error) => {
          console.log(error);
        },
      });
  }


  updatePassword() {
    this.router.navigateByUrl("Change-Password")
  }

  updateProfile() {
    if (this.profileForm.valid) {
      const updatedData = this.profileForm.value;

      this.userService
        .updateUserProfile(this.user.id, updatedData)
        .pipe(
          tap(() => {
            this.openSnackBar("Profile updated successfully!", "");
            this.userService.Profile()
              .subscribe((data: User) => {
                this.user = data;
                this.cdRef.detectChanges();
              });
          })
        )
        .subscribe(
          () => {},
          (error) => {
            if (error.status === 405) {
              this.openSnackBar("User with that email already exists!", "");
              //alert('User with that email already exists!');
            }
            //console.error('Error updating profile', error);

          }
        );
    }
  }

  updateUsername() {
    if (this.usernameForm.valid) {
      const newUsername = this.usernameForm.value.newUsername;

      this.authService
        .changeUsername(this.user.username, newUsername)
        .subscribe(
          (response) => {
            this.openSnackBar("Username updated successfully!", "")
            //console.log('Username updated successfully');
            localStorage.clear()
            this.router.navigate([""])
          },
          (error) => {
            if (error.status === 409) {
              this.openSnackBar("User with that username already exists!", "")
              //alert('User with that username already exists!');
            }
            else if (error.status === 503 ) {
              this.openSnackBar("User service is currently unavailable. Please try again later.", "");
            }
            console.error('Error updating username', error);
          }
        );
    }
  }

  deleteAccount(){
    this.openSnackBar2("Are you sure you want to delete account?", "Yes")
    .subscribe(() => {
      this.deleteAccountLogic();
    });

  }

  deleteAccountLogic() {
    this.authService.deleteAccount().subscribe(
      () => {
        this.openSnackBar2("User account deleted successfully!", "")
        console.log('User account deleted successfully!');
        setTimeout(() => {
          localStorage.clear();
          this.router.navigate(['']);
        }, 2000);

      },
      (error) => {
        if (error.status === 503) {
          this.openSnackBar("Service is currently unavailable. Please try again later.", "");
        }
        else if (error.status === 502) {
          this.openSnackBar("Service is currently unavailable. Please try again later.", "");
        }else {
          this.openSnackBar("" + error.error + "", "")
          console.error('Error deleting user account:', error);
        }
      }
    );
  }

  openSnackBar2(message: string, action: string): Observable<void> {
    const snackBarRef: MatSnackBarRef<SimpleSnackBar> = this._snackBar.open(message, action, {
      duration: 3500
    });

    return snackBarRef.onAction();
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }


}
