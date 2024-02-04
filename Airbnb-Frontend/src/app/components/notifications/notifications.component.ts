import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';
import {UserService} from "../../services/user.service";
import {User} from "../../models/user.model";
import {NotificationsService} from "../../services/notifications.service";

export interface Notification {
  id: string; // Assuming you want to represent the ObjectID as a string
  byGuestId: string;
  forHostId: string;
  description: string;
  createdAt: string; // You might want to use a Date type here if applicable
}

@Component({
  selector: 'app-notifications',
  templateUrl: './notifications.component.html',
  styleUrls: ['./notifications.component.css']
})

export class NotificationComponent implements OnInit {

  submitted = false;
  userRole:any;
  hostId: string | undefined;
  notifications: any[] = [];

  constructor(
    private userService:UserService,
    private formBuilder: FormBuilder,
    private router: Router,
    private _snackBar: MatSnackBar,
    private notificationsService: NotificationsService
  ) { }

  ngOnInit(): void {
    this.userRole = this.userService.getRoleFromToken();

    this.userService.getUser().subscribe(
      (user: User) => {
        this.hostId = user.id;

        // Once you have the hostId, you can call the service to get notifications
        if (this.hostId) {
          this.getNotificationsByHostId(this.hostId);
        }
      },
      (error) => {
        console.error('Error getting user:', error);
      }
    );
  }

  // Function to get notifications by hostId
  getNotificationsByHostId(hostId: string): void {
    this.notificationsService.getNotificationsByHostId(hostId).subscribe(
      (notifications) => {
        // Sort the notifications array by createdAt in descending order
        this.notifications = notifications.sort((a: Notification, b: Notification) => {
          const dateA = new Date(a.createdAt).getTime();
          const dateB = new Date(b.createdAt).getTime();
          return dateB - dateA;
        });
      },
      (error) => {
        console.error('Error getting notifications:', error);
      }
    );
  }

  openSnackBar(message: string, action: string) {
    this._snackBar.open(message, action,  {
      duration: 3500
    });
  }

}
