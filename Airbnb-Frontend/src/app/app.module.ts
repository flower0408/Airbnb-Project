import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';

import { MatCardModule } from '@angular/material/card';
import { MatButtonModule} from '@angular/material/button';
import { MatMenuModule } from '@angular/material/menu';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatIconModule } from '@angular/material/icon';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import {MatFormFieldModule} from '@angular/material/form-field';
import {MatSelectModule} from '@angular/material/select';
import { MatDividerModule } from '@angular/material/divider';
import { MatSnackBarModule } from '@angular/material/snack-bar';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { MainPageComponent } from './components/main-page/main-page.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { HeaderComponent } from './components/header/header.component';
import { NavigationComponent } from './components/navigation/navigation.component';
import { RegisterComponent } from './components/register/register.component';
import { LoginComponent } from './components/login/login.component';
import { AuthInterceptor } from './services/auth.interceptor';
import {AccountConfirmationComponent} from "./components/account-confirmation/account-confirmation.component";
import { RecoveryEnterMailComponent } from './components/recovery-enter-mail/recovery-enter-mail.component';
import { RecoveryEnterTokenComponent } from './components/recovery-enter-token/recovery-enter-token.component';
import { RecoveryNewPasswordsComponent } from './components/recovery-new-passwords/recovery-new-passwords.component';
import { MyProfileComponent } from './components/my-profile/my-profile.component';
import {ChangePasswordComponent} from "./components/change-password/change-password.component";
import { NgxCaptchaModule } from 'ngx-captcha';
import { CreateAccommodationComponent } from './components/create-accommodation/create-accommodation.component';
import {AccommodationDetailsComponent} from "./components/accommodation-details/accommodation-details.component";
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatInputModule } from '@angular/material/input';
import { MatNativeDateModule } from '@angular/material/core';
import { UserReservationsComponent } from './components/user-reservations/user-reservations.component';
import { HostProfileComponent } from './components/host-profile/host-profile.component';
import { NotificationComponent } from "./components/notifications/notifications.component";

@NgModule({
  declarations: [
    AppComponent,
    MainPageComponent,
    HeaderComponent,
    NavigationComponent,
    RegisterComponent,
    LoginComponent,
    AccountConfirmationComponent,
    RecoveryEnterMailComponent,
    RecoveryEnterTokenComponent,
    RecoveryNewPasswordsComponent,
    MyProfileComponent,
    ChangePasswordComponent,
    CreateAccommodationComponent,
    AccommodationDetailsComponent,
    UserReservationsComponent,
    HostProfileComponent,
    NotificationComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    BrowserAnimationsModule,
    FormsModule,
    ReactiveFormsModule,
    MatButtonModule,
    MatMenuModule,
    MatToolbarModule,
    MatIconModule,
    MatCardModule,
    MatFormFieldModule,
    MatSelectModule,
    MatDividerModule,
    MatSnackBarModule,
    ReactiveFormsModule,
    NgxCaptchaModule,
    MatDatepickerModule,
    MatInputModule,
    MatNativeDateModule
  ],
  providers:
  [{
    provide: HTTP_INTERCEPTORS,
    useClass: AuthInterceptor,
    multi: true,
  }],
  bootstrap: [AppComponent]
})
export class AppModule { }
