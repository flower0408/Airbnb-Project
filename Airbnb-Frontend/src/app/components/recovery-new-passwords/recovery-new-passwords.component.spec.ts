import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RecoveryNewPasswordsComponent } from './recovery-new-passwords.component';

describe('RecoveryNewPasswordsComponent', () => {
  let component: RecoveryNewPasswordsComponent;
  let fixture: ComponentFixture<RecoveryNewPasswordsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ RecoveryNewPasswordsComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RecoveryNewPasswordsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
