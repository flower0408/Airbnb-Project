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
import {LoginGuardService} from "./guards/login-guard.service";
import {RoleGuardService} from "./guards/role-guard.service";
import {AccommodationDetailsComponent} from "./components/accommodation-details/accommodation-details.component";
import { UserReservationsComponent } from './components/user-reservations/user-reservations.component';
import {NotificationComponent} from "./components/notifications/notifications.component";

const routes: Routes = [
  {
    path: 'Main-Page',
    component: MainPageComponent
  },

  {
    path: 'Notifications',
    component: NotificationComponent,
    canActivate: [RoleGuardService],
    data: {expectedRoles: 'Host'}
  },

  {
    path: 'AccommodationDetails/:id',
    component: AccommodationDetailsComponent
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
    canActivate: [RoleGuardService],
    data: {expectedRoles: 'Host|Guest'}

  },

  {
    path: 'Change-Password',
    component: ChangePasswordComponent,
    canActivate: [RoleGuardService],
    data: {expectedRoles: 'Host|Guest'}
  },

  {
    path: '',
    component: LoginComponent,
    canActivate: [LoginGuardService]
  },
  {
    path: 'createAccommodation',
    component: CreateAccommodationComponent,
    canActivate: [RoleGuardService],
    data: {expectedRoles: 'Host'}

  },
  {
    path: 'myReservations',
    component: UserReservationsComponent,
    canActivate: [RoleGuardService],
    data: {expectedRoles: 'Guest'}

  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
