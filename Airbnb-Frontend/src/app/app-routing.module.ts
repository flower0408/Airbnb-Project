import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './components/login/login.component';
import { MainPageComponent } from './components/main-page/main-page.component';
import { RegisterComponent } from './components/register/register.component';
import {AccountConfirmationComponent} from "./components/account-confirmation/account-confirmation.component";
import {RecoveryEnterMailComponent} from "./components/recovery-enter-mail/recovery-enter-mail.component";
import {RecoveryEnterTokenComponent} from "./components/recovery-enter-token/recovery-enter-token.component";
import {RecoveryNewPasswordsComponent} from "./components/recovery-new-passwords/recovery-new-passwords.component";
import {MyProfileComponent} from "./components/my-profile/my-profile.component";
import {ChangePasswordComponent} from "./components/change-password/change-password.component";
import { CreateAccommodationComponent } from './components/create-accommodation/create-accommodation.component';

const routes: Routes = [
  {
    path: 'Main-Page',
    component: MainPageComponent
  },

  {
    path: 'Register',
    component: RegisterComponent
  },

  {
    path: 'Account-Confirmation',
    component: AccountConfirmationComponent
  },

  {
    path: 'Request-Recovery',
    component: RecoveryEnterMailComponent
  },
  {
    path: 'Recovery-Token',
    component: RecoveryEnterTokenComponent
  },
  {
    path: 'Recovery-Password',
    component: RecoveryNewPasswordsComponent
  },

  {
    path: 'My-Profile',
    component: MyProfileComponent,
  },

  {
    path: 'Change-Password',
    component: ChangePasswordComponent,
  },

  {
    path: '',
    component: LoginComponent
  },
  {
    path: 'createAccommodation',
    component: CreateAccommodationComponent
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
