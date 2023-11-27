import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import {User} from "../../models/user.model";
import {UserService} from "../../services/user.service";
import {FormBuilder, FormGroup, Validators} from "@angular/forms";
import {AuthService} from "../../services/auth.service";
import {MatSnackBar} from "@angular/material/snack-bar";

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
              private _snackBar: MatSnackBar,){
    this.usernameForm = this.fb.group({
      newUsername: ['', Validators.required]
    });
  }

  user: User = new User();
  usernameForm: FormGroup;

  ngOnInit(): void {

    this.userService.Profile()
      .subscribe({
        next: (data: User) => {
          this.user = data;
        },
        error: (error) => {
          console.log(error);
        },
      });
  }

  updatePassword() {
    this.router.navigateByUrl("Change-Password")
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
            console.error('Error updating username', error);
          }
        );
    }
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }


}
