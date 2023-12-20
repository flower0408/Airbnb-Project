import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ActivatedRoute, Router } from '@angular/router';
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

  constructor(private userService:UserService,private fb: FormBuilder, private _snackBar: MatSnackBar, private router: Router,private accommodationService: AccommodationService, private route: ActivatedRoute) {

  }

  ngOnInit(): void {

    this.addRateForm = this.fb.group({
      rate: [1, [Validators.required]]
    });

    this.getRatesByHost();

  }

  getRatesByHost(): void {
    const username = this.route.snapshot.paramMap.get('username');
    if (username) {
      this.userService.getUserByUsername(username).subscribe(
        (user: User) => {
          this.host = user;
          this.accommodationService.getRatesByHost(this.host?.id).subscribe(
            (data: Rate[]) => {
              if(data.length > 0){
                this.rates = data;
                this.rates.forEach(rate => {
                  this.userService.getUserById(rate.byGuestId).subscribe(
                    (user: User) => {
                      rate.byGuestId = user.username;
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
          console.error('Error creating rate:', error);
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
