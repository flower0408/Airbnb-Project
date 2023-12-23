import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar, MatSnackBarRef, SimpleSnackBar } from '@angular/material/snack-bar';
import { ActivatedRoute, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { Rate } from 'src/app/models/rate.model';
import { User } from 'src/app/models/user.model';
import { AccommodationService } from 'src/app/services/accommodation.service';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-host-profile',
  templateUrl: './host-profile.component.html',
  styleUrls: ['./host-profile.component.css']
})
export class HostProfileComponent implements OnInit {

  host: User|undefined;
  rates: Rate[] = [];
  rateSum: number = 0;
  addRateForm!: FormGroup;
  loggedUser: string="";
  editRateForm!: FormGroup;
  showEditRateBool = false;

  constructor(private userService:UserService,private fb: FormBuilder, private _snackBar: MatSnackBar, private router: Router,private accommodationService: AccommodationService, private route: ActivatedRoute) {

  }

  ngOnInit(): void {

    this.addRateForm = this.fb.group({
      rate: [1, [Validators.required]]
    });

    this.editRateForm = this.fb.group({
      editedRate: [1, [Validators.required]]
    });

    this.getRatesByHost();
    this.getLoggedUser();
  }

  getRatesByHost(): void {
    const username = this.route.snapshot.paramMap.get('username');
    if (username) {
      this.userService.getUserByUsername(username).subscribe(
        (user: User) => {
          this.host = user;
          this.accommodationService.getRatesByHost(this.host?.id).subscribe(
            (data: Rate[]) => {
              if(data !== null && data.length > 0){
                this.rates = data;
                this.rates.forEach(rate => {
                  this.userService.getUserById(rate.byGuestId).subscribe(
                    (user: User) => {
                      rate.user = user;
                      this.rateSum = this.rateSum + rate.rate
                    },
                    (error) => {
                      console.error('Error getting user:', error);
                    }
                  );
                });
              }             
            },
            (error) => {
              console.error(error);
            }
          );
        },
        (error) => {
          console.error('Error getting user:', error);
        }
      );
    }
  }

  getLoggedUser(){
    this.userService.getUser().subscribe(
      (user: User) => {
        this.loggedUser = user.id;
      },
      (error) => {
        console.error('Error getting user:', error);
      }
    );
  }

  onSubmitAddRate(){

    if (this.addRateForm.valid) {

      const formValues = this.addRateForm.value;

      const newRate: any = {
        forHostId: this.host?.id,
        rate: Number(formValues.rate) 
      };

      this.accommodationService.createRateHost(newRate).subscribe(
        () => {

          this.openSnackBar("Rate created successfully!", "")
          console.log('Rate created successfully!');
          setTimeout(() => {
            window.location.reload();
          }, 2000);

        },
        (error) => {
          if (error.status === 502) {
            this.openSnackBar('Service is not currently available, please try later!', "");
          }
          this.openSnackBar(error.error, "")
          setTimeout(() => {
            window.location.reload();
          }, 2000);
          console.error('Error creating rate:', error);
        }
      );

    }

  }

  onSubmitEditRate(id:any){

    if (this.editRateForm.valid) {

      const formValues = this.editRateForm.value;

      const newRate: any = {
        rate: Number(formValues.editedRate) 
      };

      this.accommodationService.updateRate(id,newRate).subscribe(
        () => {

          this.openSnackBar("Rate changed successfully!", "")
          console.log('Rate changed successfully!');
          setTimeout(() => {
            window.location.reload();
          }, 2000);

        },
        (error) => {
          if (error.status === 502) {
            this.openSnackBar('Service is not currently available, please try later!', "");
          }
          console.error('Error changing rate:', error);
        }
      );

    }
  }

  showEditRate(){
    this.showEditRateBool = !this.showEditRateBool
  }

  deleteRate(id:any){
    this.openSnackBar2("Are you sure you want to delete your rate?", "Yes")
    .subscribe(() => {
      this.deleteRateLogic(id);
    });

  }

  deleteRateLogic(id:any) {
    this.accommodationService.deleteRate(id).subscribe(
      () => {
        this.openSnackBar2("Your rate deleted successfully!", "")
        console.log('Your rate deleted successfully!');
        setTimeout(() => {
          window.location.reload();
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
          console.error('Error deleting rate:', error);
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
